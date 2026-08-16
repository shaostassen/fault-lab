"""Cross-backend agreement gate: Unicorn vs QEMU on the identical binary.

The QEMU backend exists to answer "is the Unicorn result an artifact of the CPU
emulator?" -- and it earned its place by finding that the answer is no for the
security conclusions, and yes for one specific thing (Unicorn does not model
Cortex-M exception entry). None of that was protected against regression.

What this gate asserts is deliberately narrow, because the two backends are
known to disagree in one place and a gate that forbids all disagreement would
be wrong:

  * the unfaulted golden run must agree on verdict, marks AND instruction
    count for `forged` -- the vector every headline number is computed on, and
    the one measured to contain no predicated-false instructions;
  * both hardened -O2 survivors must still reproduce as SEC_BYPASS with a
    genuine ACCEPT verdict under a full machine model.

Skips cleanly when qemu-system-arm is absent, so a machine without it still
runs the rest of the suite rather than reporting a failure it cannot fix.
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faultlab.campaign import _CTX, _init_worker, _run_one, golden_length
from faultlab.faults import Fault, FaultModel, FaultSet, Outcome
from faultlab.target import Target, boot_vectors, V_BOOT_ACCEPT

FW = Path(__file__).resolve().parents[2] / "firmware" / "build"
BUILD = FW / "secureboot-hardened-O2"
SURVIVORS = [(8105, 4), (8106, 4)]


def main() -> int:
    if shutil.which("qemu-system-arm") is None:
        print("qemu-system-arm not installed — skipping cross-validation gate")
        return 0

    from faultlab.backend.qemu_backend import QemuBackend

    t = Target.load(BUILD)
    vec = {v.name: v for v in boot_vectors()}["forged"]
    glen, _, _ = golden_length(str(BUILD), vec)
    failures = []

    # 1. Golden run: same binary, same start state, both backends.
    with _CTX.Pool(1, initializer=_init_worker,
                   initargs=(str(BUILD), vec, "boot", glen, 16)) as p:
        # A trigger far past the end is a no-op fault: it never fires, so this
        # is the unfaulted run measured through the ordinary campaign path.
        u = p.map(_run_one, [FaultSet((Fault(10**9, FaultModel.SKIP, value=1),))])[0]

    with QemuBackend(t) as q:
        q.start(str(BUILD / "fw.elf"))
        q.reset(vec.writes(t))
        res, _ = q.trace(glen * 3)

    for label, uval, qval in (("verdict", u.verdict, res.oracle.verdict),
                              ("marks", u.marks, res.oracle.marks),
                              ("instructions", glen, res.instructions)):
        ok = uval == qval
        print(f"  golden {label:13s} unicorn={uval!r:12s} qemu={qval!r:12s} "
              f"{'ok' if ok else 'MISMATCH'}")
        if not ok:
            failures.append(f"golden {label}: unicorn={uval!r} qemu={qval!r}")

    # 2. The headline finding must survive a full machine model.
    for trig, width in SURVIVORS:
        fs = FaultSet((Fault(trig, FaultModel.SKIP, value=width),))
        with _CTX.Pool(1, initializer=_init_worker,
                       initargs=(str(BUILD), vec, "boot", glen, 16)) as p:
            urow = p.map(_run_one, [fs])[0]
        with QemuBackend(t) as q:
            q.start(str(BUILD / "fw.elf"))
            qres = q.run(glen * 3, faults=fs, writes=vec.writes(t))

        u_bypass = urow.outcome == Outcome.SEC_BYPASS
        q_bypass = qres.oracle.verdict == V_BOOT_ACCEPT
        ok = u_bypass and q_bypass
        print(f"  survivor skip@{trig},k={width}  unicorn="
              f"{Outcome(urow.outcome).name:11s} qemu_verdict={qres.oracle.verdict:#06x}  "
              f"{'ok' if ok else 'MISMATCH'}")
        if not ok:
            failures.append(f"survivor {trig}/{width}: unicorn_bypass={u_bypass} "
                            f"qemu_accept={q_bypass}")

    if failures:
        print("\nCROSS-VALIDATION GATE FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("\ncross-validation gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
