# Campaign results

All numbers below are measured output from `python -m faultlab.cli matrix`,
regenerated after six harness bugs were found and fixed (documented below —
all six silently corrupted results, in both directions: inflating findings
that weren't real, and, in bug 6's case, also masking real ones).

Determinism is gated by `harness/tests/test_determinism.py`: same binary, same
fault set, worker counts 1/2/4/8, identical exploitable sets required.

Target: Cortex-M3, `arm-none-eabi-gcc` 15.3.1 (Arm GNU Toolchain 15.3.Rel1),
Unicorn 2.1.4. Fault model: instruction skip, k in {1,2,3,4}, exhaustive over
the full golden trace. (Earlier measurements in this project's history used
13.2.1; the baseline vulnerable-build numbers drift with compiler version --
see "Compiler sweep" -- the hardened numbers do not.)

## Secure boot: hardening works, and the call site was the whole story

Bypasses (single fault, exhaustive):

| build | forged | rollback | bad_magic | golden len |
|---|---|---|---|---|
| base -O0 | 62 | 23 | 16 | 11,344 |
| **hardened -O0** | **0** | **0** | **0** | 23,745 |
| base -O2 | 22 | 9 | 6 | 3,890 |
| hardened -O2 | 2 | 0 | 0 | 8,119 |
| base -Os | 24 | 8 | 4 | 4,311 |
| hardened -Os | 2 | 0 | 0 | 9,103 |

**Every hardened cell except `-O2`/forged and `-Os`/forged is now fully
closed** -- including `-O0`, which is not what the first version of this table
said (see bug 5 below: the original `-O0` row was 4/4/4, entirely a
classifier artifact). At `-O2` and `-Os`, rollback and bad-magic are fully
closed: no single instruction skip anywhere in either trace accepts a
rolled-back or malformed image.

### The finding that mattered

The first campaign, before call-site hardening existed, gave hardened -O2 three
residual bypasses on forged and six on rollback. Localising them by symbol showed
**every single one was in `main`, not in the verifier**. The countermeasures had
closed 100% of in-function bypasses. What survived was this:

```c
if (verify_image_hardened(...) == VERIFY_PASS) { jump_to_app(hdr); }
```

The verifier returned a protected sentinel and the caller threw that protection
away with one unprotected compare-and-branch. Hardening a *function* and
hardening a *decision* are different things.

Fix: a capability-token pattern. `jump_to_app` takes the sentinel as an argument
and re-tests it before committing, so reaching the accept path is not sufficient
to boot -- carrying a valid token is. Reject is the fall-through default, so a
skipped branch lands in reject. Rollback and bad_magic went 6 -> 0 and 6 -> 0.

Aggregate counts alone would have read the original result as "countermeasures
barely helped" (3 vs 4). Localisation is what turned it into an actionable fix.

## Compiler sweep

Baseline, forged vector: **62 bypasses at -O0 vs 22 at -O2**. Unoptimised code
spills and reloads everything, so there are far more individually-skippable
instructions between a decision and its consequence. Debug builds are not just
slower, they are a materially larger attack surface. (These specific counts
are compiler-version-sensitive -- see the note at the top of this document --
but the *shape* of the result, -O0 substantially worse than -O2/-Os for the
unhardened build, is not.)

**The hardened build does not invert this, and saying so was this project's
biggest single mistake.** An earlier version of this document reported
hardened `-O0` as 4/4/4, the *worst* hardened configuration, against `-O2`'s
2/0/0 -- a clean, intuitive-sounding story (debug builds are worse, hardening
can't fully fix that) that was completely wrong. Bug 5 below found hardened
`-O0` is actually 0/0/0: fully closed, better than every other build in the
matrix. All four of the original "4/4/4" bypasses were the same classifier
artifact, and `-O0`'s 23,745-instruction trace (3x `-O2`'s) simply gave that
artifact roughly 3x more instructions to spuriously land on. The lesson
generalizes past this one bug: a result that produces a satisfying narrative
is not thereby more likely to be correct, and "the numbers moved in the
direction the story predicted" is exactly the condition under which a
confident wrong number is least likely to get double-checked.

### The two `-O2` survivors: agreement is not validation

Disassembly diff against the `-O0` build ruled out the obvious suspect first:
C2's divergently-duplicated checks are *not* folded at `-O2`. Every `if (x)
return FAIL; if (!(x)) return FAIL;` pair survives as two structurally distinct
comparisons in `verify_image_hardened`'s object code. The optimiser did not
remove the countermeasure.

The actual gap is in what C4 checks. The signature stage runs two independent
hash-and-compare passes and gates on four conditions in sequence:

```c
if (cmp_a != 0)                        return VERIFY_FAIL;
if (cmp_b != 0)                        return VERIFY_FAIL;
if (cmp_a != cmp_b)                    return VERIFY_FAIL;
if (memcmp_ct(d1, d2, 32) != 0)        return VERIFY_FAIL;
```

The first two are the only checks that validate against a known-good value
(zero). The last two only check that the **two redundant computations agree
with each other** -- and for an unmodified forged image, they always do: `d1`
and `d2` are both computed correctly (the fault never touches the hash math,
only the control flow), so they consistently mismatch the tag in the same way.
`cmp_a == cmp_b` and `d1 == d2` hold regardless of whether the image is
legitimate. C4's redundancy defends against a fault that makes the two passes
*diverge* from each other; it adds nothing against a fault that just removes
the branch checking one of them against zero, because everything downstream of
that branch is an agreement check a real forged image already satisfies.

Both surviving faults are 4-instruction skips (`FaultModel.SKIP`, `k=4`),
triggered at instruction counts 8105 and 8106 -- one instruction-count apart,
the coarsest-granularity view of the same blind spot. Mapped to addresses in
`secureboot-hardened-O2/fw.lst`:

```
56e: ldr  r2, [sp, #16]      ; cmp_a
570: cmp  r2, #0
572: bne.n 4d8 <...+0x70>    ; reject if cmp_a != 0
574: ldr  r2, [sp, #20]      ; cmp_b
576: cmp  r2, #0
578: bne.n 4d8 <...+0x70>    ; reject if cmp_b != 0
57a: ldr  r1, [sp, #16]      ; cmp_a != cmp_b starts here
```

A skip fault is applied by decoding `k` instructions forward **from the
current PC in memory order** (`UnicornBackend._skip_bytes`) and jumping past
their combined byte width -- it does not follow branches. Trigger 8105 lands
with PC at `0x570` and skips the 8 bytes spanning `cmp_a`'s compare-and-branch
plus `cmp_b`'s load-and-compare, landing exactly on `0x578`. Trigger 8106
starts one instruction later, at `0x572`, and skips both `bne` branches
outright, landing on `0x57a` -- past both zero-checks, straight into the
mutual-agreement checks that a forged image passes for free.

Confirmed on `arm-none-eabi-gcc` 15.3.1 (Arm GNU Toolchain 15.3.Rel1); the
survivor count and addresses are unchanged from the 13.2.1 baseline measured
above, so this is a codegen-independent property of the check structure, not
an artifact of one compiler version. (Baseline `-O2`/forged does drift with
compiler version -- 24 at 13.2.1 vs 32 at 15.3.1 -- but that cell is the
deliberately-unhardened control and isn't the claim being made here.)

**The fix is not "add a fifth check."** Any check reachable only through the
same control-flow gate has the same blind spot. What's missing is validating
`cmp_a` and `cmp_b` against zero *independently of the branch that currently
does it* -- e.g. folding the zero-check into the CFI accumulator (C3) so a
skipped branch also produces a wrong CFI value at the C5 re-verification,
rather than leaving zero-validation resting on a single pair of `bne`s with no
redundant path to the same conclusion.

## Double-fault campaigns against hardened -O2

Single fault is closed for `rollback` and `bad_magic` at `-O2` (0/0 above).
Two faults might not be, and *forged* already has known single-fault bypasses,
so it doesn't test anything new by itself -- the open question is specifically
whether the two genuinely closed vectors stay closed against a two-fault
attacker.

### `rollback` and `bad_magic`: still closed, exhaustively

Both vectors halt almost immediately at `-O2` -- `bad_magic` fails the very
first check (58-instruction golden trace) and `rollback` fails the version
check before any hash work happens (74 instructions) -- so an **exhaustive**
double-fault search needed no slicing at all: every instruction in the golden
trace, all four skip widths, every pairing (`min_separation=1`).

| vector | single-fault candidates | double-fault sets | exploitable |
|---|---|---|---|
| bad_magic | 232 | 26,448 | **0** |
| rollback | 296 | 43,216 | **0** |

Zero exploitable outcomes across both, run to completion in under a second.
This is a stronger claim than the single-fault result: it is not just that no
*single* instruction skip anywhere in these traces reopens either vector, it's
that no *pair* of skips does either, at any two points, any two widths. Given
how thin these traces are, an attacker capable of two independent glitches has
essentially the whole golden run available and still can't reopen either
vector at `-O2`.

### `forged`: the seeded search was wrong. There is a novel attack surface, and it's large.

`forged`'s golden trace is 8,119 instructions -- too long to search
exhaustively at order 2 by materializing every pair up front (the full
slice-narrowed candidate set is 3,462 triggers x 4 widths = 13,848
descriptors, C(13848,2) ~= 95.9M pairs -- 96M `FaultSet` objects would exhaust
memory before any run happened). A first pass tried a bounded, seeded search
instead: 6,048 pairs drawn from SDC near-misses intersected with the slice,
plus the two known survivors. It found 22 exploitable sets, every one
containing a known survivor, and concluded there was no novel combination
effect *in that seed set*. That conclusion was correctly scoped at the time --
but the seed set turned out to be the wrong place to look.

**Full-space search**, driven with `Pool.imap_unordered()` over a lazy
`itertools.combinations()` generator instead of a materialized list -- the
same 96M pairs, streamed one at a time so memory stays flat regardless of
total count, with only exploitable rows and running counts kept (see
`harness/faultlab/slice.py`-adjacent driving code, not yet folded into
`campaign.py` proper):

| | |
|---|---|
| pairs run | 95,855,856 |
| wall time | 44.9 min (35,613 runs/s, 4 workers) |
| OK / CRASH / SDC / HANG | 86,883,270 / 6,402,215 / 954,845 / 1,613,890 |
| **exploitable** | **1,635** (0.0017% of pairs; corrected for the R0-R12 fix above) |
| -- contain a known single-fault survivor (8105 or 8106) | 429 |
| -- **novel: contain neither** | **1,206** |

**74% of exploitable double-fault sets are novel.** The 6,048-pair seeded
search from the first pass found zero of them, because it seeded from SDC
near-misses -- runs that diverge from golden behaviour -- and this attack
surface isn't made of near-misses. It's made of faults that, alone, produce
perfectly ordinary `OK` (correctly-rejected) outcomes.

**The structure, once you have the full set:** every novel bypass is a pair of
one "early" fault and one "late" fault, and the two halves behave completely
differently.

- The **late** fault is always in a 14-instruction window, triggers 8102-8115
  -- the same `cmp_a`/`cmp_b`/`cmp_a!=cmp_b`/`memcmp_ct(d1,d2)` check block
  identified above. This is the only place in `verify_image_hardened` where
  the accept/reject decision actually gets committed, so any bypass has to
  land there.
- The **early** fault ranges across essentially the *entire* trace -- 476
  distinct trigger values from 0 to 8104.

First hypothesis was that the early fault corrupts some shared register or
memory value the late check reads. **That's wrong, and it's worth recording
why**, because the actual mechanism is more interesting than that. A
`window_slice()` seeded from the check block's own register/memory reads
(`harness/faultlab/slice.py`) explains 468 of the 476 early triggers (98.3%)
by dataflow/control-flow alone -- strong, but direct instrumentation of a
representative pair (early trigger 3899, late trigger 8107) shows every
register and the one stack memory address the block reads are **bit-identical**
between "late fault alone" and "both faults" right up to the point of
divergence. Nothing is being corrupted.

**The real mechanism is in how SKIP faults interact with instruction-count
triggering itself.** `UnicornBackend._apply()` moves the PC forward by a
skipped instruction's byte width but never advances `self._instr` --
correctly, since a skipped instruction didn't execute -- but that means a
*second* fault's `trigger` in the same `FaultSet` is counted only against
instructions actually executed after the first fault, not against the golden
trace's own instruction numbering. An early skip of width `w0` shifts where a
later nominal trigger `t1` actually lands, by exactly `w0`, to golden position
`t1 + w0`.

Computing `t1 + w0` across all 1,206 novel results confirms it: the
distribution peaks sharply at **8105 (352 pairs) and 8106 (219 pairs) -- the
exact two known single-fault survivors** -- with the remaining mass
(8108-8118, ~450 pairs) landing elsewhere in the same check block, dense
enough with redundant, agreement-only checks that several nearby
offset/width combinations are independently skippable into acceptance, not
just those exact two addresses.

**This is not 1,206 independent vulnerabilities, and it is not a bug in
instruction-count triggering.** It is instruction-count triggering doing
exactly what it's specified to do -- and doing it in a way that's more
physically realistic than "golden-trace-absolute" triggering would have been:
a real glitch that skips an instruction genuinely advances the target faster
in elapsed-time terms, so a second, time-triggered glitch landing later than
planned is exactly what a real attacker's timing error would look like too.
The finding is about the check block's tolerance for that drift: it's wide
and uniform enough (multiple redundant, agreement-only checks in a row) that
an attacker who mistimes a single fault by a few instructions can often
recover the same outcome with a second, imprecise fault absorbing the error,
rather than needing to reacquire exact timing. **The single-fault result (2
exploitable instructions) understates how easy this class of attack is to
mount; the double-fault result (~14 landing points, reachable through a wide
range of timing-error-absorbing early faults) is the more operationally
honest number.**

### Why `rollback`/`bad_magic` don't have this problem

Their 0/0 result isn't an artifact of insufficient search depth. The
candidate generation already covers this: an exhaustive double-fault search
over "every nominal (early, late) trigger pair, all four widths" necessarily
also covers "every true landing position `late + early_width`," since the
early fault's width was varied across the same 1-4 range independently of
which late trigger it was paired with. The `t + w0` drift-shift the `forged`
analysis above depends on was already being exercised, exhaustively, by the
same 26,448- and 43,216-pair searches reported earlier -- there's no
undiscovered mechanism these searches were too short to reach.

The real reason is structural, and it's visible directly in the source. C2's
divergent-duplication pattern is applied to `bad_magic` and `rollback` as two
independent re-tests against a **real constant**:

```c
if (hdr->magic != IMAGE_MAGIC)    return VERIFY_FAIL;
if (!(hdr->magic == IMAGE_MAGIC)) return VERIFY_FAIL;
...
if (hdr->version < min_version)     return VERIFY_FAIL;
if (!(hdr->version >= min_version)) return VERIFY_FAIL;
```

Both forms of each check compare directly against `IMAGE_MAGIC` /
`min_version` -- an attacker has to defeat two genuinely independent
comparisons against ground truth. Compare that to C4's signature check (the
`-O2` survivor section above): `cmp_a != cmp_b` and `memcmp_ct(d1, d2, 32)`
don't compare against a constant at all, they compare two *derived* values
against **each other**. For a forged image with an unfaulted hash
computation, those two derived values agree by construction, so the
agreement checks add no defense against skipping the checks that matter. The
double-fault campaign's structural finding, stated once and for all: **C2
divergent duplication is exactly as strong as what each duplicate compares
against.** Against a real constant, it holds under both single- and
double-fault search. Against a second, correctly-computed but
un-independently-validated value, it doesn't.

## Safety supervisor: software hardening does not close this

| build | overcurrent | deadline_miss | runs | golden | rate |
|---|---|---|---|---|---|
| base -O2 | 71 | 68 | 212/224 | 53/56 | 31.9% |
| hardened -O2 | 118 | 120 | 432/456 | 108/114 | 26.8% |
| base -O0 | 125 | 126 | 508/524 | 127/131 | 24.3% |
| hardened -O0 | 188 | 190 | 1124/1160 | 281/290 | 16.5% |

(Corrected for bug 6 below -- `classify_supervisor()` had the same
marks-accumulator exposure bug 5 found in the boot classifier, confirmed by
direct audit, not by inference from the boot fix. The correction moves every
cell, in both directions -- see bug 6 -- but the qualitative shape survives
unchanged: hardening only marginally reduces the violation rate, and the
`-O2`/`-O0` comparison stays in the same order.)

Raw counts went **up** with hardening. They are not comparable across builds: the
hardened trace is roughly 2x longer, so there are 2x more injection sites.
Normalised to violation rate per run, `-O2` goes 31.9% -> 26.8%. Marginal.

That marginal result is the finding, and it is not a failure of the
countermeasures. The classifier checks the safety invariant *before* it checks
for crashes, so a fault that wedges the CPU before safe state is entered counts
as a violation. That ordering is deliberate and correct: **a crashed MCU with a
PWM peripheral still driving is a safety violation**, and the peripheral does not
stop because the core faulted.

The engineering conclusion follows directly: for a safety oracle, fail-closed
cannot be achieved in software alone. No amount of shadowed state or duplicated
guards defends against the core stopping. That needs an independent watchdog
driving the gate-driver enable low on timeout. This is a real design requirement
in motor control, and the campaign produces the argument for it rather than
asserting it.

Note the asymmetry with the bootloader. A security oracle is one decision at
attacker-chosen timing, and software countermeasures close it almost completely.
A safety oracle is a continuously re-evaluated invariant, and they barely move it.

### Watchdog model: closes about half the gap, and exactly which half is the finding

An independent hardware watchdog needs a specific timeout to simulate in full
-- but picking one is picking an arbitrary number, and the interesting claim
doesn't depend on it. A liveness watchdog's entire job, at any timeout, is to
catch a CPU that has stopped responding. So split every `SAFETY_VIOLATION`
above by `halt_reason` instead of simulating a specific timer: did the CPU
actually stop (`CPUFAULT`/`BUDGET` -- a watchdog catches this by definition,
regardless of the exact timeout chosen), or did it run to a clean halt with
the wrong state (`ORACLE` -- a liveness watchdog cannot distinguish this from
correct operation, at any timeout, because nothing about it looks like
non-responsiveness)?

| build | vector | violations | CPU stopped | CPU alive, wrong | watchdog closes |
|---|---|---|---|---|---|
| base -O2 | overcurrent | 71 | 43 | 28 | 60.6% |
| base -O2 | deadline_miss | 68 | 43 | 25 | 63.2% |
| hardened -O2 | overcurrent | 118 | 70 | 48 | 59.3% |
| hardened -O2 | deadline_miss | 120 | 72 | 48 | 60.0% |
| base -O0 | overcurrent | 125 | 51 | 74 | 40.8% |
| base -O0 | deadline_miss | 126 | 51 | 75 | 40.5% |
| hardened -O0 | overcurrent | 188 | 93 | 95 | 49.5% |
| hardened -O0 | deadline_miss | 190 | 93 | 97 | 48.9% |
| **total** | | **1,006** | **516** | **490** | **51.3%** |

**An independent watchdog closes about half the gap, not all of it.** The
other half -- 490 of 1,006 across this matrix -- is a CPU that never stops:
it halts cleanly via `oracle_halt()`, on schedule, with a fault having
corrupted *which* state it reports rather than whether it keeps running. No
watchdog timeout, however short, catches that, because there's no
non-responsiveness to time out on.

Looking closer at that second half: 95%+ of them (471 of 490, tallied per
build/vector) have `pwm_duty` correctly at `0` and only `sup_state` wrong --
the state-machine bookkeeping fails to land on `SUP_SAFE` while the one
output that actually drives the motor is already off. That is genuine
partial credit for the hardened build's redundancy (the physically dangerous
output is usually right even when the run is classified a violation), but it
does not make the finding go away: the invariant this project set out to test
is `sup_state == SAFE AND pwm_duty == 0`, both terms, and a `sup_state` that
silently disagrees with reality is exactly the kind of corrupted bookkeeping
that downstream logic (re-arm conditions, fault logging, a human reading a
status register) would trust and shouldn't.

**The complete engineering conclusion, not just "add a watchdog":** an
independent liveness watchdog is necessary but provably not sufficient here.
It's the right fix for the crash/hang half of the gap, cleanly, and nothing
else fixes that half as simply. The other half needs a mitigation that
doesn't depend on CPU liveness at all -- e.g. an independent hardware trip on
the actual gate-driver output (monitoring current or duty cycle directly,
not trusting software's internal state variable), since by construction nothing
that watches "is the CPU still running" can ever catch "the CPU is running
fine and confidently wrong."

## Throughput

~200-9,300 runs/s depending on trace length and worker count. Two honest notes:

- **`workers=1` is often fastest** on short campaigns (9,321/s vs 3,531/s at 8
  workers on the 15,580-run sweep). Spawn re-imports the module per worker and
  each worker builds its own 16-rung ladder; below roughly 50k runs that startup
  cost dominates. Scale workers to campaign size, do not default to core count.
- The win that made this viable at all is **no code hook during campaign runs**.
  `emu_start(count=N)` advances exactly N instructions with zero Python
  callbacks. A `UC_HOOK_CODE` callback at ~1 us/instruction would make the
  32,520-run hardened campaign take ~4 minutes instead of ~7 seconds.

## Six harness bugs, all silent

This is the most useful section in the document.

### 1. Corrupted telemetry read as a finding (INFLATED results)

The classifier tested `marks & MARK_JUMP_TAKEN` without validating `marks`.
Faults that corrupted the oracle struct wrote RAM addresses into that word --
`0x20000037` has bit 4 set -- so every such run was reported as a bypass. The
campaign showed the *hardened* build with 25 bypasses against baseline's 4: a
fabricated 6x regression.

Fix: `oracle_trustworthy()` -- magic intact, no undefined mark bits, verdict in
the valid set -- checked before any field is interpreted.

### 2. Writable FLASH leaking state between runs (SUPPRESSED results)

`restore()` only restores RAM, because copying 256 KB of flash per run would
dominate runtime. But FLASH was mapped `UC_PROT_ALL`, so a faulted store could
corrupt it, and that corruption **persisted into every subsequent run handled by
the same worker**, crashing them early.

This suppressed findings, and the suppression scaled with how many runs shared a
backend: the same campaign reported 4 bypasses at 1/2/4 workers and 24 at 8. The
true answer is 24. Lower parallelism was *more* wrong.

Fix: map FLASH `READ|EXEC`. This is also what the real part does -- Cortex-M
flash is not writable by a plain store, it needs a controller unlock sequence --
so a faulted store into flash now raises a CPU fault and classifies as CRASH.

### 3. fork() inherits emulator state (NONDETERMINISM)

Before the flash fix masked it, the same campaign in the same process returned 4
on eleven runs and 24 on the twelfth. Unicorn wraps QEMU's TCG, which holds
C-level global state; `multiprocessing`'s default `fork()` on Linux copies it
into every child, and merely having executed `import unicorn` in the parent is
enough. Fixed with `mp.get_context("spawn")` plus keeping the parent
emulator-free by running the golden trace in a throwaway child.

### 4. `reset()` left R0-R12/LR undefined by call-order accident (small INFLATED result)

Found by the double-fault campaign below, not by inspection. `reset()` only
ever wrote SP and PC explicitly. `_init_worker()` calls `trace()` -- a full,
unfaulted golden run -- *before* `build_ladder()` calls `reset()` again and
snapshots rung 0. Since `reset()` never touched R0-R12/LR, rung 0 silently
inherited whatever those registers held at the *end* of the golden trace, not
a clean reset state. Real Cortex-M3 silicon does leave R0-R12 architecturally
undefined after reset, but "undefined" has to mean one deliberate, documented
value, not an accident of which function happened to run last.

Impact was narrow, not sweeping: real code overwrites every register within
the first few instructions, so only a fault triggered at instruction 0
exactly -- skipping Reset_Handler's very first register load -- could read the
contaminated value before anything legitimate overwrote it. Of the 1,636
exploitable double-fault results found below, exactly 3 had `trigger=0`. Under
a rerun with R0-R12/LR explicitly zeroed, one of those three stopped
reproducing -- a `SEC_BYPASS` that existed only because of leftover
golden-trace register state, not because of anything an attacker could cause.
The other two survived the fix unchanged, confirming they're real. Corrected
totals: **1,635 exploitable, 1,206 novel** (both figures below already
reflect the fix).

Fix: `reset()` now explicitly zeroes R0-R12 and LR. Determinism and regression
gates rerun clean afterward with identical single-fault numbers throughout --
this bug never touched any previously-reported single-fault result, since none
of them are triggered at instruction 0.

### 5. `marks` used as an accept signal, corruptible the same way verdict was (bug 1, again, in a place bug 1's fix didn't reach) -- LARGE INFLATED result, one withdrawn finding

This is the big one. Found while chasing what looked like the most exciting
result of the project: an order-3 (triple-fault) exhaustive search against
`rollback` and `bad_magic` -- both exhaustively proven closed against one and
two faults above -- found 96 and 36 "exploitable" triples respectively. The
draft of this document briefly called that a genuine escalation: countermeasures
holding at low fault order, giving way at three faults.

**It wasn't real, and the way it fell apart is worth walking through.**
`classify_boot()` computed `accepted = (verdict == V_BOOT_ACCEPT) or (marks &
MARK_JUMP_TAKEN)`. Checking the `verdict` field on the "exploitable" triples
before believing them: **zero of the 96 `bad_magic` results had `verdict ==
V_BOOT_ACCEPT`.** All 96 had `verdict == 0` -- the run never reached *any*
`oracle_halt()` call. All 36 `rollback` results had **`verdict ==
V_BOOT_REJECT`** -- the firmware's own recorded verdict said reject, and the
classifier called it a bypass anyway, purely from the marks bit.

The mechanism: `oracle_mark()` compiles to a read-modify-write --
`ldr r2,[r3,#8]` (load current marks), `orr.w r2,r2,#2` (OR in a bit),
`str r2,[r3,#8]` (store back). A skip fault that removes the *load* leaves
`r2` holding whatever it last held -- in the traced case, `(hdr->length - 1)
XOR hdr->magic` from an unrelated, also-fault-disrupted CFI computation a few
instructions earlier. That value happened to already have bit 4 set. OR in
`HDR_OK`'s bit, store it back, and `marks & MARK_JUMP_TAKEN` reads true despite
no `jump_to_app()` call anywhere in the execution -- confirmed by tracing the
full instruction stream, which never leaves `verify_image_hardened` and
`memcpy` before the instruction budget runs out.

This is structurally bug 1 again -- corrupted telemetry with the right bit
set, indistinguishable from a real finding unless checked -- in a spot bug 1's
fix doesn't cover. `oracle_trustworthy()` checks "no undefined bits in
`marks`," and a stale register holding real firmware data (a length, a magic
value) easily falls entirely within the *defined* 9-bit range by chance,
especially for small values. The check that caught bug 1's failure mode
(implausibly large corrupted values, like a RAM address) has nothing to say
about a small, plausible-looking one.

**Why `verdict` doesn't have this exposure and `marks` does:** `verdict` is
set by one direct store of a sparse, high-Hamming-distance constant (see
`oracle.h`) -- no load, no accumulation, nothing stale to inherit. `marks` is
an accumulator by design (see the design note in `oracle.h`: it exists so the
harness can reconstruct a control-flow path without a full trace), and every
accumulator has this load-bearing load. The `MARK_JUMP_TAKEN` OR-clause was
presumably added to catch a fault that reaches the accept decision but
disrupts the verdict *write* itself -- but `oracle_halt()` already guards
that case with a trailing `for(;;){}` (see its comment: "guards against a
skipped store"), which the harness sees as `HANG`, not a silent accept. The
marks fallback was not just unsafe, it was unnecessary.

**Fix:** `accepted = (verdict == V_BOOT_ACCEPT)`, full stop. Both gates rerun
clean. Then came the expensive part -- checking whether this contaminated
anything already reported:

- The `-O2` two-survivor finding and the double-fault campaign (1,635
  exploitable / 1,206 novel): **clean.** Replaying the two single-fault
  survivors and all 1,207 novel double-fault triggers (across all four
  possible widths for the untracked second fault) directly, every single one
  has genuine `verdict == V_BOOT_ACCEPT`. Nothing in this document's
  double-fault section needed to change.
- **The regression baseline table did not survive.** A full matrix re-run
  with the fix applied changed five of the six unhardened-vs-hardened cells
  (new numbers are in the table at the top of this document and in
  CLAUDE.md). The starkest: hardened `-O0` went from 4/4/4 to **0/0/0** --
  see "Compiler sweep" above. `-O0`'s much longer trace gave the artifact
  proportionally more chances to fire, which is exactly backwards from what
  the original table implied (that debug builds are less securable even when
  hardened).
- **The triple-fault finding itself is withdrawn.** Whether `rollback` and
  `bad_magic` are actually closed against three faults is, as of this
  writing, unknown again -- a real open question, not a settled one, and it's
  in "Next" below.

**The generalisable lesson, again, sharper this time: fixing a silent-corruption
bug once, in one place, does not mean the failure mode is gone.** Bug 1 and
bug 5 are the *same* root cause -- a harness trusting a telemetry field
without verifying it was produced by the code path it claims to represent --
recurring in a second field with a different, more accumulator-shaped attack
surface. The check that stops bug 1 from recurring verbatim (no undefined
bits) does not generalize to stopping its sibling. And this one was caught
only because a review discipline held under pressure: the result was the most
exciting number in the whole project, arrived right when the work was
already deep into a long session, and got checked against ground truth
(`verdict`) before being written up as fact rather than after.

### 6. Same bug as 5, in the supervisor classifier -- confirmed by audit, not assumed

Bug 5's writeup ended with an item in CLAUDE.md's Open work list: audit
`classify_supervisor()`, which reads `marks & MARK_SAFE_ENTERED` in
structurally the same way `classify_boot()` read `marks & MARK_JUMP_TAKEN`,
for the same reason (a read-modify-write accumulator, corruptible by a fault
that skips the load). That audit is what this is -- not an inference from
bug 5, an independent empirical check.

Method: for every single-fault run across all four supervisor builds and both
`fault_asserted` vectors (`overcurrent`, `deadline_miss`), compare `marks &
MARK_SAFE_ENTERED` against `sup_state == SUP_SAFE` directly (`sup_state` is a
plain `uint32_t` field the classifier already tracks but wasn't using for this
check). They disagreed 22 to 58 times per build/vector -- never zero, across
every single build. Both directions occurred:

- **Marks claims safety, `sup_state` says otherwise** (would mask a real
  `SAFETY_VIOLATION`): `marks=0x180` (`FAULT_ASSERTED | SAFE_ENTERED`) paired
  with `sup_state` still `SUP_INIT` (`0x11`), or in a few cases outright
  wild-pointer garbage -- `sup_state=0x40010004` (the `ORACLE_MARK` MMIO
  address) and `sup_state=0x20000034` (`g_image`'s address) both appeared,
  the same corrupted-pointer signature as bug 1's original failure.
- **`sup_state` says safety was reached, marks disagrees** (would fabricate a
  `SAFETY_VIOLATION` that didn't happen): `sup_state=0x88` (`SUP_SAFE`,
  genuinely reached) paired with `marks=0x80` -- `FAULT_ASSERTED` set,
  `SAFE_ENTERED`'s bit simply never OR'd in.

Unlike bug 5, this one is symmetric: it can produce false negatives (missed
violations, the dangerous direction for a safety classifier) and false
positives (fabricated ones) with roughly comparable frequency, since nothing
about `oracle_mark()`'s corruption mechanism favors one direction over the
other -- which specific bit a stale register happens to carry is arbitrary.

Fix: `entered_safe = (o.sup_state == SUP_SAFE)`, mirroring bug 5's fix
exactly and for the identical reason -- `sup_state` is a direct store of a
sparse constant (`0x11`/`0x22`/`0x44`/`0x88`) in every assignment in
`safety.c`, never a load-modify-store, so it isn't exposed to a skipped-load
corruption the way `marks` is. Both gates rerun clean. The corrected
supervisor table is above; unlike bug 5's retraction of the `-O0` conclusion,
this correction moves every cell but **does not reverse the qualitative
finding** -- hardening still only marginally reduces the violation rate, and
the `-O2` vs `-O0` ordering is unchanged. Worth stating plainly: that the
conclusion survived this time was not knowable in advance of running the
audit, and "the fix probably won't change the story" is exactly the kind of
assumption bug 5 exists to discourage.

**The generalisable lesson from all six, stated once: a fault injection
harness must be adversarial about its own instrumentation, its own memory
model, its own concurrency, and its own idea of "undefined" -- and "adversarial"
has to be re-applied to every new telemetry field and every new fault order,
not assumed to transfer from the last field or order it was applied to.** Bug
6 is the clearest demonstration of that last clause in this document: knowing
bug 5's exact mechanism did not make bug 6 optional to check, because the
question was never "does this codebase have the bug class" -- it was "does
this specific field, in this specific classifier, have it," and the only way
to answer that is to look. All six bugs were silent, all six produced
confident wrong numbers, and three of them (1, 5, and directionally 6)
pointed toward fabricated findings rather than suppressed ones. A fabricated
bypass survives review far longer than a missing one.

## Threats to validity

- Instruction skip is an **abstraction** of what a voltage or clock glitch
  physically does. The mapping is approximate and model-dependent.
- No pipeline, no cache, no analog behaviour.
- **Random-delay countermeasures get zero credit** under instruction-count
  triggering -- the emulator's clock is not the attacker's clock. This harness
  would report them ineffective. That is an artifact of the method.
- SHA-256 keyed tag stands in for Ed25519 on runtime budget (~4k instructions vs
  ~10-20M). Structurally identical for fault purposes, one crypto result feeding
  one compare-and-branch, but it is a substitution and named as one.
- Simulated campaigns establish **necessary** conditions for exploitability, not
  sufficient ones. Hardware validation is the follow-up, not an optional extra.

## Next

1. ~~**Characterize the early-fault mechanism.**~~ — done, see RESULTS.md
   ("the seeded search was wrong. There is a novel attack surface, and it's
   large"). Not register/memory corruption (ruled out by direct
   instrumentation, register-identical up to the point of divergence). It's
   that `_apply()` never advances `self._instr` for a SKIP fault, so a second
   fault's trigger is counted against actually-executed instructions, not
   golden-trace position -- an early skip of width `w0` shifts a later nominal
   trigger `t1`'s true landing point to `t1 + w0`. That value clusters at 8105
   and 8106 across 571 of 1,206 novel pairs. Not a triggering bug: it's a
   physically realistic model of timing drift after a real glitch, and the
   finding is that the vulnerable check block tolerates that drift over a wide
   range rather than requiring exact timing.
2. ~~**Explain the asymmetry with `rollback`/`bad_magic`.**~~ — done, see
   RESULTS.md ("Why `rollback`/`bad_magic` don't have this problem"). Not a
   search-depth gap -- the earlier exhaustive search already exercised every
   true landing position the drift mechanism can reach. It's structural: their
   C2 duplicate checks compare directly against a real constant (`IMAGE_MAGIC`,
   `min_version`), where the signature check's C4 duplicates compare two
   *derived* values against each other. Divergent duplication is exactly as
   strong as what each duplicate validates against.
3. ~~**GA search**~~ — done, `harness/faultlab/ga.py`. Dynamic-slice-seeded
   population, marks-progress fitness (partial credit toward the golden run's
   checkpoint bits), tournament selection, crossover, mutation, and random
   immigrants each generation against premature convergence. Validated by
   rediscovering a real order-2 `forged`/hardened-`-O2` bypass from scratch in
   9 generations. This is also the tool for the item below.
4. ~~**Redo the triple-fault search on `rollback`/`bad_magic`.**~~ — done,
   with the fixed classifier: **both genuinely closed, exhaustively, 0/0**
   (1,974,784 and 4,148,736 triples). The withdrawn 96/36 result was entirely
   the bug 5 artifact; the real answer is a clean confirmation, not a
   different vulnerability.
5. ~~**Audit `classify_supervisor()`.**~~ — done, see RESULTS.md bug 6. It had
   the same failure, confirmed by direct empirical audit (comparing `marks &
   MARK_SAFE_ENTERED` against `sup_state` on every single-fault supervisor
   run, not inferred from bug 5): 22-58 mismatches per build/vector, in both
   directions (would-mask and would-fabricate). Fixed the same way bug 5 was
   fixed. The supervisor table above is corrected; the qualitative conclusion
   (hardening only marginally helps) survived, unlike bug 5's `-O0` reversal.
6. ~~**Independent watchdog model**~~ — done, see "Watchdog model: closes
   about half the gap" above. Split existing `SAFETY_VIOLATION` results by
   `halt_reason` rather than simulating one specific timeout (a liveness
   watchdog catches CPU-stopped at *any* reasonable timeout, so the split is
   timeout-independent): **51.3% of violations are a CPU that stopped
   responding** (a watchdog closes these by definition) **and 48.7% are a CPU
   that completed a clean halt with the wrong state** (no watchdog timeout
   catches this, ever -- there's no non-responsiveness to time out on).
   Watchdog is necessary, not sufficient; the remaining half needs a mitigation
   that doesn't depend on CPU liveness, e.g. a hardware trip on the actual
   gate-driver output.
7. MicroBlaze port, to make "architecture-independent" a claim not an aspiration.
8. QEMU backend for cross-validation; disagreement between backends localises
   where the abstraction gap changes the security conclusion.
