# faultlab

Emulation-based fault injection campaign harness for safety-critical firmware.
Finds the instruction-level corruptions that make a secure bootloader accept an
unsigned image or a motor safety supervisor miss its safe state, then measures
what countermeasures actually close.

## Layout

```
firmware/
  common/       oracle protocol, startup, linker script, minilib (memcpy etc.)
  crypto/       sha256.c -- stands in for Ed25519 on runtime budget
  secureboot/   image format, verify.c (baseline) + verify_hardened.c
  supervisor/   motor safety state machine, baseline + hardened
  Makefile      builds the {base,hardened} x {-O0,-O2,-Os} matrix
harness/
  faultlab/
    target.py                  ELF load, pinned symbols, test vectors
    faults.py                  Fault/FaultSet descriptors, campaign generation
    backend/unicorn_backend.py emulation, snapshot ladder, fault application
                                (golden trace capture lives here, in .trace())
    classify.py                outcome classification
    campaign.py                spawn pool, work distribution
    slice.py                   backward taint slice -- multi-fault candidate
                                narrowing (see CLAUDE.md Open work item 2)
    store.py                   parquet writer
    cli.py                     sweep / matrix entry points
  tests/
    test_determinism.py        THE GATE -- same result at 1/2/4/8 workers
    test_regression.py         security regression floor/ceiling gate
analysis/       heatmap.py -- self-contained interactive HTML, no build step
```

## Build

```bash
cd firmware && make matrix          # all six binaries
make VARIANT=hardened OPT=-O2 disasm
```

`disasm` exists because of the single most important sanity check in this
project: **open the hardened `-O2` listing and confirm the duplicated checks
appear twice.** If the optimiser folded them, the countermeasure is not there,
and the campaign will find that out in a much more expensive way.

## Campaign workflow

1. **Golden run.** One clean execution recording the instruction sequence,
   memory writes, final oracle state, and total instruction count. This gives
   the injection site list, the SDC ground truth, and the hang budget (3x golden).
2. **Ladder.** 16 snapshots spaced by instruction count across the golden trace.
   Spacing by count, not address, matters: the crypto is a little code executed
   an enormous number of times, so address-uniform rungs all land in one loop.
3. **Single-fault sweep.** Exhaustive over the region of interest. Week-two
   milestone. Should independently rediscover the three known-by-construction
   targets documented at the top of `verify.c` -- that rediscovery is the
   harness's correctness test.
4. **Narrow.** Backward slice from the decision branch to the instructions that
   can actually influence it. This is what makes multi-fault tractable.
5. **Multi-fault.** Combinations from the narrowed set, plus GA search over the
   residual space seeded from single-fault near-misses.
6. **Compare.** Same campaign against every binary in the matrix. Produce the
   table: exploitable single-fault sites and double-fault sites, base vs
   hardened, at each optimisation level.

## Design decisions worth defending in the writeup

**Triggering on instruction count, not PC.** Counts are deterministic and totally
ordered; PCs are ambiguous inside loops. This makes campaigns reproducible and
multi-fault tuples well-defined, and it enables the windowed-hook optimisation
that makes the whole thing fast enough to run.

**The firmware never judges itself.** It reports what it did. The harness knows
what input it supplied and owns the classification. A fault that corrupts the
firmware's self-assessment therefore cannot launder itself into a clean result.

**Two backends, cross-validated.** Unicorn for throughput, QEMU for machine
fidelity. Agreement between them is a correctness argument for the harness.
Disagreement is a *finding* -- it localises where the gap between a raw CPU
emulator and a full machine model changes the security conclusion.

## Threats to validity

State these plainly; a reviewer who knows this domain will look for them, and
naming them is worth more than another heatmap.

- Instruction skip is an *abstraction* of what a voltage or clock glitch
  physically does. The mapping is approximate and model-dependent.
- No pipeline, no cache, no analog behaviour. Fault effects that depend on
  microarchitectural state are invisible here.
- **Random-delay countermeasures get zero credit under instruction-count
  triggering**, because the emulator's clock is not the attacker's clock. This
  harness will report them as ineffective. That is an artifact of the method,
  not a property of the countermeasure.
- Simulated campaigns establish *necessary* conditions for exploitability, not
  sufficient ones. Hardware validation is the follow-up, not an optional extra.

## Status

**Working end to end.** Firmware builds for the full
{secureboot,supervisor} x {base,hardened} x {-O0,-O2,-Os} matrix; campaigns run
at 1,400-9,700 runs/s on 4 workers and find real single-fault bypasses.
See RESULTS.md for measured numbers.

Headline result: hardening closes every secure-boot cell except `-O2` and
`-Os`/forged (2 exploitable instructions each; `-O0` is fully closed, 0/0/0).
Getting there required finding that the first version of the countermeasures'
residual bypasses were at the unprotected CALL SITE, not in the verifier --
aggregate counts would have missed it entirely.

Five silent harness bugs were found and fixed along the way -- inflated
results, suppressed results, nondeterminism, an undefined-register artifact,
and (the big one) a telemetry field that could be corrupted into looking like
a real bypass, which briefly produced a fabricated "hardened `-O0` is the
worst configuration" conclusion before being caught and retracted. All five
are documented in RESULTS.md because the failure modes generalise past this
project -- bug 5 especially, since it's the same root cause as bug 1
recurring in a field bug 1's own fix didn't cover.

Determinism is gated: `python3 harness/tests/test_determinism.py`.

Backward taint slicing (`harness/faultlab/slice.py`), double-fault campaigns
against hardened `-O2` (full 95.9M-pair search, not just a seeded sample --
see RESULTS.md), a GA multi-fault search (`harness/faultlab/ga.py`), and the
supervisor watchdog model are all built -- the last of these found that an
independent watchdog closes only about half of the safety-oracle gap (the
half where the CPU actually stops; the other half is a clean halt with wrong
state, which no liveness watchdog can ever catch). See CLAUDE.md's Open work
list for current numbers and what's next -- as of this writing, that's the
QEMU backend and MicroBlaze port (in that order -- Unicorn has no MicroBlaze
support, so QEMU is the real prerequisite).

## Quickstart

```bash
cd firmware && make matrix
cd ../harness && python3 -m faultlab.cli matrix --workers 4 --out ../analysis/results
python3 ../analysis/heatmap.py        # -> analysis/heatmap.html
```

Requires `arm-none-eabi-gcc`, and `pip install unicorn capstone pyelftools pyarrow duckdb`.
