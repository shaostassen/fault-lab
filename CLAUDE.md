# CLAUDE.md

Context for agentic sessions on this repo. Read this before changing anything in
`harness/` or `firmware/`.

## What this is

An emulation-based fault injection campaign harness. It corrupts execution of
bare-metal firmware (skip instructions, flip register/memory bits) on two
architectures, Cortex-M3 and RV32I,
classifies every outcome, and measures which countermeasures actually close
which attacks. Two targets: a secure boot verifier (security oracle) and a motor
safety supervisor (safety oracle).

It is a portfolio project. The writeup and the numbers matter as much as the
code — a change that speeds something up but makes a result unexplainable is a
net loss.

## Commands

```bash
# build all 12 binaries: {secureboot,supervisor} x {base,hardened} x {-O0,-O2,-Os}
cd firmware && make matrix

# same cross product on the second architecture -> build/*-rv32
make matrix-rv32

# single build + disassembly listing
make TARGET=secureboot VARIANT=hardened OPT=-O2

# full campaign matrix -> parquet in analysis/results/
cd harness && python3 -m faultlab.cli matrix --workers 4 --out ../analysis/results

# one campaign
python3 -m faultlab.cli sweep --build ../firmware/build/secureboot-base-O2 --vector forged

# THE GATE — run after any change to campaign.py, the backend, or classify.py
python3 harness/tests/test_determinism.py

# regenerate the interactive heatmap
python3 analysis/heatmap.py
```

Requires `arm-none-eabi-gcc` (apt: `gcc-arm-none-eabi`) and
`pip install -r requirements.txt`. The RV32 target additionally needs
`riscv64-unknown-elf-gcc` (apt: `gcc-riscv64-unknown-elf`) — no libc package
is required, the firmware ships its own freestanding `common/string.h`.

## Invariants — do not violate these

Each one below was a real bug that produced confident wrong numbers. All three
were silent. Re-introducing any of them is the main risk in this codebase.

**1. FLASH is mapped `READ|EXEC`, never `UC_PROT_ALL`.**
`restore()` only restores RAM (copying 256 KB of flash per run would dominate
runtime). If flash is writable, a faulted store corrupts it and the corruption
persists into every later run in that worker. This *suppressed* findings: the
same campaign gave 4 bypasses at 1/2/4 workers and 24 at 8 workers. 24 is
correct. `reset()` bumps permissions temporarily to load the image, then drops
them back — that is the only place flash is written.

**2. Workers are spawned, never forked. The parent must never hold a `Uc`.**
Unicorn wraps QEMU's TCG, which has C-level global state. `fork()` copies it;
merely having executed `import unicorn` in the parent is enough to corrupt
children. Symptom: same campaign, same process, 4 bypasses on eleven runs and 24
on the twelfth. `campaign.py` uses `mp.get_context("spawn")` and runs the golden
trace in a throwaway child so the parent stays emulator-free.

Consequence: any script that launches a campaign needs an `if __name__ ==
"__main__":` guard, or spawn re-imports it and the process tree explodes. See
`analysis/heatmap.py`.

**3. Validate oracle well-formedness before interpreting any field.**
`classify.py::oracle_trustworthy()` checks magic, undefined mark bits, and
verdict validity. An early version tested `marks & MARK_JUMP_TAKEN` without
this; faults that corrupted the oracle struct wrote RAM addresses into that word
(`0x20000037` has bit 4 set) and every one was reported as a security bypass —
a fabricated 6x regression. Corrupted telemetry that happens to have the right
bit set is indistinguishable from a real finding unless you check.

**4. The firmware never judges itself.** It reports only what it *did*. The
harness knows what input it supplied and owns the classification. Do not add a
"did I pass" flag to `oracle_state_t` — a fault that corrupts the firmware's
self-assessment must not be able to launder itself into a clean result.

**5. Classification order is adversarial on purpose.** SEC_BYPASS and
SAFETY_VIOLATION are checked *before* CRASH and HANG. A fault that accepts the
image and then crashes is still a bypass. Checking crash first silently hides a
whole class of finding.

**6. Faults trigger on instruction count, never PC.** Counts are deterministic
and totally ordered; PCs are ambiguous inside loops. This is also what enables
the no-code-hook fast path. Changing it breaks reproducibility, multi-fault
tuple identity, and throughput at once.

**7. No `UC_HOOK_CODE` in the campaign path.** `emu_start(count=N)` advances
exactly N instructions with zero Python callbacks. A per-instruction hook costs
~1 us and would turn a 7-second campaign into 4 minutes. The code hook exists
only in `trace()`, which runs once per (target, vector).

**8. `reset()` defines every general-purpose register, not just SP/PC.**
`UnicornBackend.reset()` used to leave R0-R12 and LR untouched. `_init_worker()`
calls `trace()` (a full, unfaulted golden run) before `build_ladder()` snapshots
rung 0 — with R0-R12 undefined by `reset()`, rung 0 silently inherited whatever
registers the golden run's *last* instructions happened to leave behind, not a
clean reset state. A `trigger=0` fault that skips Reset_Handler's first
register load then read that leftover value instead of anything a real CPU
reset would produce. Found via the double-fault campaign in RESULTS.md: of
1,636 exploitable double-fault pairs, exactly 3 had `trigger=0`, and one of
those three stopped reproducing once R0-R12/LR were zeroed explicitly — a real,
if narrow, instance of the same silent-self-corruption pattern as bugs 1-3
above. `reset()` now zeroes R0-R12 and LR explicitly so "undefined" is a
documented choice, not an accident of call order.

**9. In a multi-fault `FaultSet`, a later trigger is relative to executed
instructions, not golden-trace position.** `_apply()` moves the PC forward for
a SKIP fault but never advances `self._instr` (correctly — a skipped
instruction didn't execute). Consequence: fault *N+1*'s `trigger` is counted
against instructions actually run since fault *N*, so an earlier skip of width
`w` silently shifts where a later nominal trigger `t` truly lands, to golden
position `t + w`. This is not a bug — it is arguably the physically correct
behavior, since a real glitch that skips an instruction genuinely advances the
target faster in elapsed-time terms, and a second, later, time-triggered
glitch landing on `t + w` rather than `t` is exactly what a real attacker's
timing error would produce. But it means multi-fault trigger tuples are
**cumulative, not absolute** — do not read a `FaultSet`'s later triggers as
positions in the unfaulted golden trace, and do not assume a wide spread of
"early" triggers in a multi-fault result implies a wide range of independently
vulnerable causes. See RESULTS.md's double-fault section for the case this
produced: 476 distinct early-fault trigger values that looked at first like
476 different bugs and turned out to be one drift effect landing on the same
~14 addresses.

**10. `accepted` in `classify_boot()` depends on `verdict` alone — never OR
in a `marks` bit as an alternate accept signal.** It used to:
`accepted = (verdict == V_BOOT_ACCEPT) or bool(marks & MARK_JUMP_TAKEN)`.
`marks` is updated by a read-modify-write (`ldr` current value, `orr` in a
bit, `str` back) — a skip fault that removes the *load* leaves a stale
register from whatever ran earlier to be OR'd and stored instead, and that
stale value can coincidentally have `MARK_JUMP_TAKEN`'s bit set while
containing zero undefined bits, which is invisible to `oracle_trustworthy()`.
Found via a triple-fault campaign against `rollback`/`bad_magic`: every one of
132 "exploitable" results had `verdict != V_BOOT_ACCEPT` — `rollback`'s were
`verdict == V_BOOT_REJECT` outright, the marks bit overriding an explicit,
correct REJECT. `verdict` doesn't have this exposure: it's one direct store
of a sparse constant, not an accumulator. This is bug 1's exact failure mode
(corrupted telemetry with the right bit set, indistinguishable from a real
finding unless checked) recurring in a field bug 1's fix — "no undefined bits
in marks" — does not cover, because a stale but *plausible* small value can
be entirely within the defined range. Fixing it changed the regression
baseline table above significantly, especially `hardened -O0` (4/4/4 →
0/0/0) — see RESULTS.md bug 5 for the full account, including why that
table's original "-O0 is the worst hardened config" conclusion was itself
downstream of this bug and had to be retracted.

**11. `classify_supervisor()` had invariant 10's exact bug too — checked by
audit, not assumed from the boot fix.** It read `marks & MARK_SAFE_ENTERED`,
the same read-modify-write accumulator exposure. Confirmed empirically:
across every supervisor build, single-fault sweeps of `overcurrent` and
`deadline_miss` found 22-58 runs per build/vector where `marks &
MARK_SAFE_ENTERED` disagreed with `sup_state == SUP_SAFE`, in **both**
directions — `marks` claiming safety while `sup_state` was still `SUP_INIT`
(or wild-pointer garbage, the bug-1 signature) would have masked a real
`SAFETY_VIOLATION`; `sup_state == SUP_SAFE` with the mark bit simply unset
would have fabricated one. Fixed the same way: `entered_safe = (sup_state ==
SUP_SAFE)`, since `sup_state` is a direct store of a sparse constant in
`safety.c`, same reasoning as `verdict`. Unlike invariant 10's fix, this one
did not reverse the supervisor's qualitative conclusion (hardening still only
marginally reduces violation rate) — but that was not knowable before running
the audit, which is the point: bug 5's mechanism does not tell you whether
bug 6 exists, only that it's worth checking for. See RESULTS.md bug 6.

## Architecture

```
firmware/
  common/oracle.h        firmware<->harness contract; MMIO halt/mark protocol
  common/link_cm3.ld     PINS .oracle at 0x20000000 and .noinit after it
  common/minilib.c       memcpy/memcmp/memcmp_ct — ours because memcmp is an
                         attack target and must be traced code, not libc
  common/string.h        freestanding prototypes for the above; means the
                         build needs no C library on either architecture
  common/startup_rv32.c  RV32I reset (sp set in asm — RISC-V has no
  common/link_rv32.ld    hardware SP load); same memory map as link_cm3.ld
  secureboot/verify.c              baseline verifier (NOT strawmanned)
  secureboot/verify_hardened.c     C1-C5 countermeasures
  secureboot/main.c                call site; hardened variant uses a
                                   capability-token pattern
  supervisor/safety.c              baseline + S1-S5 hardened, one file
harness/faultlab/
  target.py              ELF load, pinned symbols, test vector construction
  faults.py              Fault/FaultSet descriptors, campaign generation
  backend/isa.py         per-architecture constants (registers, mode bit,
                         instruction width) — the ONLY place the ISA differs
  backend/unicorn_backend.py   emulation, snapshot ladder, fault application
  backend/gdb_rsp.py     GDB remote-serial-protocol client for the QEMU
                         backend (MicroBlaze needs it; Unicorn has no such
                         target)
  classify.py            outcome classification — the judgement lives here
  campaign.py            spawn pool, work distribution
  slice.py               backward taint slice — narrows the candidate set
                         for multi-fault search (see Open work item 1)
  store.py               parquet writer
  cli.py                 sweep / matrix entry points
analysis/heatmap.py      self-contained interactive HTML, no build step
```

One binary serves every test vector: the linker pins `.noinit`, the harness
writes inputs there pre-reset. No rebuild per vector.

## Regression baselines

Known-good as of the last full run: `arm-none-eabi-gcc` 15.3.1, with the
invariant-10 classifier fix applied. **Both of those are load-bearing on these
exact numbers** — a different compiler version moves the `base` column (see
RESULTS.md's "Compiler sweep"), and invariant 10's fix moved literally every
cell except `hardened -O2`/forged when it landed (`hardened -O0` in
particular: 4/4/4 → 0/0/0). If a change moves these and you didn't just
change compiler or fix a classifier bug, understand why before committing.
Secure boot, single-fault skip k in {1,2,3,4}, exhaustive:

| build | forged | rollback | bad_magic |
|---|---|---|---|
| base -O0 | 62 | 23 | 16 |
| hardened -O0 | 0 | 0 | 0 |
| base -O2 | 22 | 9 | 6 |
| hardened -O2 | 2 | 0 | 0 |
| base -Os | 24 | 8 | 4 |
| hardened -Os | 2 | 0 | 0 |

Determinism gate reference: `secureboot-base-O2` / `forged` must give exactly
**22** exploitable sites at every worker count (compiler- and classifier-fix-
dependent per the note above — the determinism *test* only checks
cross-worker-count consistency, not this specific value; this number is
documentation, not an assertion in the test itself).

## Open work, roughly in order

1. ~~**Disassembly diff, hardened `-O0` vs `-O2`**~~ — done, see RESULTS.md
   ("The two `-O2` survivors: agreement is not validation"). Not a folding
   issue: C2's duplicated checks stay structurally distinct at `-O2`. The gap
   is in C4 — `cmp_a != cmp_b` and `memcmp_ct(d1, d2, 32)` only check that the
   two redundant hash passes *agree with each other*, which an unfaulted
   forged image satisfies trivially. Both survivors are 4-instruction skips
   that remove the `bne` checking one pass against zero, landing straight in
   the agreement checks.
2. ~~**Backward slicing**~~ — done, `harness/faultlab/slice.py`. Dynamic
   backward slice seeded on both the oracle verdict/marks memory locations
   (dataflow) and every conditional branch on the golden path whose static PC
   repeats at most `loop_repeat_threshold` times (control flow — see the
   module docstring for why address direction alone can't tell a decision
   branch from a loop back-edge here, and why CPSR needs a manual assist:
   capstone under-reports the implicit flags read on a conditional branch).
   Narrows `secureboot-hardened-O2`/forged from 8,119 to 3,462 candidates
   (42.6%); shorter vectors narrow further (`bad_magic` 58→36, `rollback`
   74→48). Validated against the item-1 survivors: both 8105 and 8106 are in
   the slice. Still coarse — dataflow through `memcmp_ct`'s byte-compare loop
   legitimately pulls in every byte, since the constant-time compare's result
   really does depend on all of them — so this narrows, it does not minimize.
3. ~~**Double-fault campaigns**~~ — done, see RESULTS.md ("Double-fault
   campaigns against hardened -O2"). `rollback` and `bad_magic` are
   **exhaustively confirmed closed** against two faults (26,448 and 43,216
   pairs, 0 exploitable). `forged`'s full 95.9M-pair slice space was searched
   (streamed via `Pool.imap_unordered()` over a lazy combinations generator,
   not materialized — 96M `FaultSet` objects up front would have exhausted
   memory) and found **1,635 exploitable double-fault sets, 1,206 of them
   novel** — not explained by either known single-fault survivor, all
   independently confirmed genuine (`verdict == V_BOOT_ACCEPT`) after bug 5
   below raised the question of whether any "exploitable" count could be
   trusted at all. The mechanism turned out to be instruction-count drift,
   not a wide blind spot — see RESULTS.md and invariant 9 above.

   Finding this also surfaced a fourth silent harness bug (RESULTS.md,
   "Six harness bugs" §4, and invariant 8 above): `reset()` left R0-R12/LR
   undefined, so `trigger=0` faults could read golden-trace leftover register
   state instead of a defined reset value. Fixed; both gates rerun clean.
4. ~~**GA search**~~ — done, `harness/faultlab/ga.py`. Validated by
   rediscovering a real order-2 bypass from scratch. Used to drive at a
   genuinely new question (order-3 search on `rollback`/`bad_magic`) which is
   how it surfaced invariant 10 above — the fifth harness bug, and the
   largest correction this project has made: it retracted the "hardened -O0
   is the worst configuration" conclusion (real answer: 0/0/0, best in the
   matrix) and invalidated a from-scratch triple-fault "finding" that had
   briefly looked like the most exciting result in the whole project. See
   RESULTS.md bug 5 for the full account — it's the one worth reading if you
   only read one section of that document.
5. ~~**Redo the triple-fault search on `rollback`/`bad_magic`**~~ — done,
   with the fixed classifier: both **genuinely, exhaustively closed against
   three faults** (1,974,784 and 4,148,736 triples, 0/0). The withdrawn 96/36
   result was entirely bug 5's artifact.
6. ~~**Audit `classify_supervisor()`**~~ — done, see invariant 11 and
   RESULTS.md bug 6. It had the same failure — confirmed by direct audit
   (comparing `marks & MARK_SAFE_ENTERED` against `sup_state` on every
   single-fault supervisor run), not assumed from bug 5. 22-58 mismatches per
   build/vector, both directions (would-mask and would-fabricate). Fixed;
   supervisor table in RESULTS.md corrected; qualitative conclusion survived.
7. ~~**Independent watchdog model**~~ — done, see RESULTS.md ("Watchdog
   model: closes about half the gap"). Split `SAFETY_VIOLATION` results by
   `halt_reason` instead of simulating one arbitrary timeout — a liveness
   watchdog catches "CPU stopped" at any reasonable timeout, so the split
   itself is the timeout-independent version of the claim. Result: 51.3%
   of violations are the CPU actually stopping (`CPUFAULT`/`BUDGET` — a
   watchdog closes these by definition), 48.7% are a clean halt with wrong
   state (`ORACLE` — no watchdog timeout ever catches this). Necessary, not
   sufficient: the fail-closed argument holds, but "add a watchdog" alone
   only gets you half of "closes the gap."
8. ~~**Second architecture**~~ — done for RV32I, see RESULTS.md ("Second
   architecture: RV32I, and hardening is 3x weaker on it"). Unicorn has a
   RISC-V target, so this did NOT need the QEMU backend; `ISA=rv32` in the
   firmware Makefile plus `backend/isa.py` descriptors carry it. Qualitative
   claim replicates (hardened `-O0` is 0/0/0 on both; rollback and bad_magic
   closed at every `-O` level on both); hardening is 3x weaker on RV32I
   against `forged` (23→7 vs 22→2 at `-O2`). Caveat that matters: the two
   toolchains are different GCC majors (15.3.1 vs 14.2.0), which this project
   already knows moves baseline counts — so the quantitative gap is
   confounded, the qualitative replication is not.

   The supervisor replicates too, including its *negative* result: hardening
   moves the violation rate 31.9→26.8% (ARM) and 29.0→23.7% (RV32) at `-O2`,
   and the watchdog closes 51.3% vs 55.6%. And multi-fault sharpens the
   picture — `rollback`/`bad_magic` are exhaustively closed on BOTH
   architectures at orders 1 and 2, but **at order 3 ARM stays closed (0/0)
   while RV32 does not (29 and 14 genuine bypasses)**, every distinct trigger
   tuple replayed from reset on a fresh backend to confirm. Same C
   countermeasures, less depth on RV32I.

   **MicroBlaze** still needs a cross-compiler that does not exist in apt —
   `qemu-system-microblaze` is installed and `backend/qemu_backend.py` is
   generic apart from its board table, but without a compiler there is no
   firmware. Xilinx Vitis or a crosstool-ng build.
9. ~~**QEMU backend**~~ — done, `harness/faultlab/backend/qemu_backend.py`,
   driving `qemu-system-arm -M mps2-an385` over `backend/gdb_rsp.py`. That
   board is a Cortex-M3 with SRAM at 0x00000000 and 0x20000000, i.e. exactly
   `link_cm3.ld`'s map, so it runs the **identical** `fw.elf` with no relink —
   which is what makes a disagreement a finding rather than a link-address
   artifact. Both `-O2` survivors reproduce under it (SEC_BYPASS/ACCEPT on
   both backends), so the headline security result is not a Unicorn artifact.

   It found one real disagreement, documented in RESULTS.md: **Unicorn does
   not count predicated-false Thumb-2 IT-block instructions as executed, and
   QEMU does** (QEMU matches silicon here). Since faults trigger on
   instruction count, trigger indices are Unicorn coordinates — self-consistent
   across this project, but not identical to a real part's retired-instruction
   count. Measured impact on reported numbers: none. The `forged` path every
   headline figure comes from contains no predicated-false instructions and
   matched QEMU exactly at 8,119; only the `genuine` control vector diverges.

   Quantified over 82 runs stratified by outcome class: **100% agreement
   (62/62) on OK, SDC, HANG and SEC_BYPASS — every class that carries a
   security conclusion — and the entire divergence confined to CRASH** (2/20
   agree there). One cause: **Unicorn does not model Cortex-M exception entry,
   so `startup_cm3.c`'s `HardFault_Handler` never runs under it**, while QEMU
   vectors into it and the firmware halts with `V_ASSERT_FAIL` as designed.
   A second contributor is invariant 1 — Unicorn's flash is `READ|EXEC`, while
   `mps2-an385` has writable SRAM at 0x0 (it is an FPGA board, not a part with
   real flash), so faulted stores into code succeed there.

   **Consequence worth knowing before trusting the watchdog number:** the
   supervisor's 51.3% "a watchdog closes this" figure splits violations by
   `halt_reason`, and CRASH is precisely the class the backends disagree on.
   A fault that vectors into `HardFault_Handler` on silicon halts *cleanly*
   rather than stopping the CPU, moving it into the half no watchdog closes.
   Treat 51.3% as an upper bound until the supervisor is run through the QEMU
   backend (cheap — those traces are ~100 instructions, not 8,119).

   Two limits: it is a cross-validation oracle, not a campaign engine (one RSP
   round trip per guest instruction, ~21k steps/s vs Unicorn's ~45k runs/s),
   and it is Cortex-M3 only — QEMU's RISC-V boards put DRAM at 0x80000000, so
   RV32 would need relinking and would no longer be the same bytes.

## Conventions

- Comments explain *why*, especially where a choice looks wrong but is
  deliberate (early-exit `memcmp`, SHA-256 standing in for Ed25519, adversarial
  classification order). Those comments are load-bearing for the writeup.
- Results claims go in `RESULTS.md` with the measured number, never rounded up
  or hand-waved. Threats to validity stay in the document.
- New countermeasures need a campaign before and after, not just an assertion
  that they help.
