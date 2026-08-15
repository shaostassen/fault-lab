# CLAUDE.md

Context for agentic sessions on this repo. Read this before changing anything in
`harness/` or `firmware/`.

## What this is

An emulation-based fault injection campaign harness. It corrupts execution of
bare-metal Cortex-M3 firmware (skip instructions, flip register/memory bits),
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
`pip install -r requirements.txt`.

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

## Architecture

```
firmware/
  common/oracle.h        firmware<->harness contract; MMIO halt/mark protocol
  common/link_cm3.ld     PINS .oracle at 0x20000000 and .noinit after it
  common/minilib.c       memcpy/memcmp/memcmp_ct — ours because memcmp is an
                         attack target and must be traced code, not libc
  secureboot/verify.c              baseline verifier (NOT strawmanned)
  secureboot/verify_hardened.c     C1-C5 countermeasures
  secureboot/main.c                call site; hardened variant uses a
                                   capability-token pattern
  supervisor/safety.c              baseline + S1-S5 hardened, one file
harness/faultlab/
  target.py              ELF load, pinned symbols, test vector construction
  faults.py              Fault/FaultSet descriptors, campaign generation
  backend/unicorn_backend.py   emulation, snapshot ladder, fault application
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

Known-good as of the last full run. If a change moves these, understand why
before committing. Secure boot, single-fault skip k in {1,2,3,4}, exhaustive:

| build | forged | rollback | bad_magic |
|---|---|---|---|
| base -O0 | 69 | 30 | 23 |
| hardened -O0 | 4 | 4 | 4 |
| base -O2 | 24 | 11 | 8 |
| hardened -O2 | 2 | 0 | 0 |
| base -Os | 30 | 17 | 7 |
| hardened -Os | 3 | 1 | 0 |

Determinism gate reference: `secureboot-base-O2` / `forged` must give exactly
**24** exploitable sites at every worker count.

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
3. ~~**Double-fault campaigns**~~ — partially done, see RESULTS.md
   ("Double-fault campaigns against hardened -O2"). `rollback` and `bad_magic`
   are **exhaustively confirmed closed** against two faults (26,448 and 43,216
   pairs, 0 exploitable — these traces are short enough to brute-force fully,
   no slicing needed). `forged` got a bounded 6,048-pair search seeded from
   SDC near-misses ∩ the item-2 slice, unioned with the two known survivors:
   0 novel double-fault-only bypasses, but every one of the 22 exploitable
   pairs found just combines a known survivor with an inert second fault —
   this covers a small fraction of the ~96M-pair full slice space, not all of
   it. Full-space search on `forged` is RESULTS.md's next item.
4. **Independent watchdog model** for the supervisor. The current result says
   fail-closed is unachievable in software — model a watchdog that drives
   gate-driver enable low on timeout and show it closes the gap.
5. **MicroBlaze port** — second architecture makes "architecture-independent" a
   claim rather than an aspiration. Also the detail that makes this project
   unmistakably the author's, since that is the soft core he ships on.
6. **QEMU backend** for cross-validation. Agreement is a correctness argument;
   disagreement localises where the emulator abstraction changes the security
   conclusion, which is itself a finding.

## Conventions

- Comments explain *why*, especially where a choice looks wrong but is
  deliberate (early-exit `memcmp`, SHA-256 standing in for Ed25519, adversarial
  classification order). Those comments are load-bearing for the writeup.
- Results claims go in `RESULTS.md` with the measured number, never rounded up
  or hand-waved. Threats to validity stay in the document.
- New countermeasures need a campaign before and after, not just an assertion
  that they help.
