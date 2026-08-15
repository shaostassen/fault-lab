"""Outcome classification.

THE CENTRAL RULE: the firmware reports only what it DID. This module knows what
input was supplied and therefore owns the judgement. A fault that corrupts the
firmware's self-assessment cannot launder itself into a clean result, because
the firmware's self-assessment is never consulted as ground truth.

Classification order matters and is deliberately adversarial: a run is checked
for SEC_BYPASS and SAFETY_VIOLATION *before* it is checked for CRASH or HANG.
A fault that both corrupts state and then crashes is still a bypass if it
accepted the image on the way down. Checking crash first would silently hide
an entire class of finding.
"""

from __future__ import annotations

from .faults import Outcome
from .target import (
    OracleState, V_BOOT_ACCEPT, V_BOOT_REJECT, V_SAFE_STATE,
    V_RUN_COMPLETE, V_ASSERT_FAIL, BootVector, SupervisorVector,
)
from .backend.unicorn_backend import HaltReason, RunResult

MARK_JUMP_TAKEN = 1 << 4
MARK_FAULT_ASSERTED = 1 << 7
MARK_SAFE_ENTERED = 1 << 8

# Only bits 0..8 are defined marks. Anything above means the marks word itself
# was corrupted, and it must NOT be interpreted as flags.
MARKS_DEFINED_MASK = (1 << 9) - 1

VALID_VERDICTS = {V_BOOT_ACCEPT, V_BOOT_REJECT, V_SAFE_STATE,
                  V_RUN_COMPLETE, V_ASSERT_FAIL, 0}


def oracle_trustworthy(o: OracleState) -> bool:
    """Is the observation channel itself intact?

    THIS CHECK EXISTS BECAUSE OF A REAL FALSE POSITIVE. An early version tested
    `marks & MARK_JUMP_TAKEN` without validating `marks`. Faults that corrupted
    the oracle struct wrote RAM addresses into the marks word -- 0x20000037 has
    bit 4 set, so every one of them was reported as a security bypass. The
    campaign showed the HARDENED build with 6x more bypasses than baseline,
    which was entirely an artifact of this.

    The general lesson, and it belongs in the writeup: a fault injection harness
    must be adversarial about its own instrumentation. Corrupted telemetry that
    happens to have the right bit set is indistinguishable from a real finding
    unless you check. Well-formedness first, interpretation second.
    """
    return (o.valid
            and (o.marks & ~MARKS_DEFINED_MASK) == 0
            and o.verdict in VALID_VERDICTS)


def classify_boot(res: RunResult, vec: BootVector, golden: RunResult) -> Outcome:
    o: OracleState = res.oracle

    # The oracle struct is in RAM. If the observation channel itself is
    # corrupted, nothing downstream can be trusted -- and critically, a garbage
    # marks word must never be interpreted as flags. See oracle_trustworthy().
    if not oracle_trustworthy(o):
        return Outcome.CRASH

    # `marks` used to be OR'd in here too (accepted if EITHER verdict said so
    # OR the JUMP_TAKEN bit was set), meant to catch a fault that reaches the
    # accept decision but disrupts the verdict write itself. It doesn't work:
    # marks is a read-modify-write accumulator (load current marks, OR in a
    # bit, store back), and a fault that skips the LOAD leaves a stale
    # register -- holding unrelated data from whatever ran before -- to be
    # OR'd and stored in its place. That stale value can coincidentally have
    # bit 4 set with no undefined bits elsewhere, which is indistinguishable
    # from a real MARK_JUMP_TAKEN to oracle_trustworthy(). Found via a
    # triple-fault campaign against rollback/bad_magic: every one of 96+36
    # "exploitable" results had verdict != V_BOOT_ACCEPT -- rollback's were
    # verdict == V_BOOT_REJECT outright, the marks bit overriding an explicit,
    # correctly-recorded REJECT. verdict doesn't have this exposure: it's a
    # single direct store of a sparse, high-Hamming-distance constant (see
    # oracle.h), not an accumulator, so there's no stale-load path into it.
    # And if a fault skips the verdict WRITE itself, oracle_halt()'s trailing
    # `for(;;){}` traps execution -- caught as HANG, not silently accepted --
    # so marks was never actually needed as a fallback for that case.
    accepted = (o.verdict == V_BOOT_ACCEPT)

    # --- adversarial checks first ------------------------------------------
    if accepted and not vec.should_accept:
        return Outcome.SEC_BYPASS

    # Rollback specifically: accepted an image below the version floor. Caught
    # by the check above via should_accept, but assert it independently so a
    # mis-specified vector cannot silently hide a real bypass.
    if accepted and o.image_version < vec.min_version:
        return Outcome.SEC_BYPASS

    # --- then failure modes ------------------------------------------------
    if res.halt_reason == HaltReason.CPUFAULT:
        return Outcome.CRASH
    if o.verdict == V_ASSERT_FAIL:
        return Outcome.CRASH
    if res.halt_reason == HaltReason.BUDGET:
        return Outcome.HANG

    # --- then correctness --------------------------------------------------
    if accepted != vec.should_accept:
        # Rejected something genuine: denial of service. A finding, but a much
        # less interesting one than the converse.
        return Outcome.SDC
    if o.marks != golden.oracle.marks:
        # Same verdict, different control-flow path. Worth surfacing: it is
        # often the near-miss that seeds the multi-fault search.
        return Outcome.SDC
    return Outcome.OK


def classify_supervisor(res: RunResult, vec: SupervisorVector,
                        golden: RunResult) -> Outcome:
    o: OracleState = res.oracle
    if not oracle_trustworthy(o):
        return Outcome.CRASH

    # THE SAFETY INVARIANT:
    #     fault_asserted => sup_state == SAFE and pwm_duty == 0
    # Checked against the vector's ground truth, not the firmware's opinion of
    # whether it noticed the fault.
    if vec.fault_asserted:
        entered_safe = bool(o.marks & MARK_SAFE_ENTERED)
        if not entered_safe or o.pwm_duty != 0:
            return Outcome.SAFETY_VIOLATION

    if res.halt_reason == HaltReason.CPUFAULT:
        return Outcome.CRASH
    if o.verdict == V_ASSERT_FAIL:
        return Outcome.CRASH
    if res.halt_reason == HaltReason.BUDGET:
        return Outcome.HANG

    if o.pwm_duty != golden.oracle.pwm_duty or o.sup_state != golden.oracle.sup_state:
        return Outcome.SDC
    if o.marks != golden.oracle.marks:
        return Outcome.SDC
    return Outcome.OK


def is_exploitable(outcome: Outcome) -> bool:
    """The two classes that are actual security/safety findings. Everything
    else is robustness noise -- interesting for reliability, not for the
    threat model."""
    return outcome in (Outcome.SEC_BYPASS, Outcome.SAFETY_VIOLATION)
