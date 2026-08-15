# Campaign results

All numbers below are measured output from `python -m faultlab.cli matrix`,
regenerated after three harness bugs were found and fixed (documented below —
all three silently corrupted results, in opposite directions).

Determinism is gated by `harness/tests/test_determinism.py`: same binary, same
fault set, worker counts 1/2/4/8, identical exploitable sets required.

Target: Cortex-M3, `arm-none-eabi-gcc` 13.2.1, Unicorn 2.1.4. Fault model:
instruction skip, k in {1,2,3,4}, exhaustive over the full golden trace.

## Secure boot: hardening works, and the call site was the whole story

Bypasses (single fault, exhaustive):

| build | forged | rollback | bad_magic | golden len |
|---|---|---|---|---|
| base -O0 | 69 | 30 | 23 | 11,344 |
| hardened -O0 | 4 | 4 | 4 | 23,745 |
| base -O2 | 24 | 11 | 8 | 3,895 |
| **hardened -O2** | **2** | **0** | **0** | 8,130 |
| base -Os | 30 | 17 | 7 | 4,422 |
| hardened -Os | 3 | 1 | 0 | 9,263 |

90-100% reduction in every cell. At `-O2` the rollback and bad-magic vectors are
**fully closed**: no single instruction skip anywhere in an 8,130-instruction
trace accepts a rolled-back or malformed image.

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

Baseline, forged vector: **69 bypasses at -O0 vs 24 at -O2**. Unoptimised code
spills and reloads everything, so there are far more individually-skippable
instructions between a decision and its consequence. Debug builds are not just
slower, they are a materially larger attack surface.

The hardened build inverts this: `-O0` is the *worst* hardened configuration
(4/4/4) and `-O2` the best (2/0/0). Explaining the two `-O2` forged survivors
via disassembly diff is the next open item.

## Safety supervisor: software hardening does not close this

| build | overcurrent | deadline_miss | runs | golden |
|---|---|---|---|---|
| base -O2 | 61 | 61 | 212/224 | 53/56 |
| hardened -O2 | 115 | 117 | 436/460 | 109/115 |
| base -O0 | 130 | 131 | 508/524 | 127/131 |
| hardened -O0 | 195 | 191 | 1124/1160 | 281/290 |

Raw counts went **up** with hardening. They are not comparable across builds: the
hardened trace is roughly 2x longer, so there are 2x more injection sites.
Normalised to violation rate per run, `-O2` goes 28.8% -> 26.4%. Marginal.

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

## Three harness bugs, all silent

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

**The generalisable lesson: a fault injection harness must be adversarial about
its own instrumentation, its own memory model, and its own concurrency.** All
three bugs were silent, all three produced confident wrong numbers, and one of
them pointed in the direction that would have gotten published. A fabricated
bypass survives review much longer than a missing one.

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

1. Disassembly diff of hardened `-O0` vs `-O2` to explain the two survivors.
2. Backward slicing to narrow the multi-fault space, then double-fault campaigns
   against hardened `-O2`. Single fault is closed; two may not be.
3. Independent watchdog model for the supervisor, per the fail-closed argument.
4. MicroBlaze port, to make "architecture-independent" a claim not an aspiration.
5. QEMU backend for cross-validation; disagreement between backends localises
   where the abstraction gap changes the security conclusion.
