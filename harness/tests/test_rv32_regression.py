"""Security regression gate for the second architecture.

The Cortex-M gate (test_regression.py) protected the only architecture that
existed when it was written. RV32I now carries a claim of its own -- that the
same C countermeasures close rollback and bad_magic completely on both ISAs,
and that hardening measures roughly 3x weaker on RV32I against forged -- and
nothing was checking it. A codegen change, a toolchain bump, or a harness
regression could move any of those numbers silently.

Same shape as the Cortex-M gate and for the same reasons: ceilings rather than
exact matches, so a genuine improvement is not a red build, plus a FLOOR on the
deliberately-vulnerable baseline, because a gate that only asserts "few enough"
passes trivially when the harness stops finding anything at all.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faultlab.campaign import run_campaign, golden_length
from faultlab.faults import FaultModel, single_fault_sweep
from faultlab.target import boot_vectors, V_BOOT_ACCEPT

FW = Path(__file__).resolve().parents[2] / "firmware" / "build"

# (build, vector, ceiling) -- measured values in RESULTS.md's cross-architecture
# table. Hardened rollback/bad_magic are at ZERO on both architectures and must
# stay there: that is the qualitative claim the RV32 port exists to support.
CASES = [
    ("secureboot-hardened-O2-rv32", "rollback", 0),
    ("secureboot-hardened-O2-rv32", "bad_magic", 0),
    ("secureboot-hardened-O0-rv32", "forged", 0),
    ("secureboot-hardened-O0-rv32", "rollback", 0),
    ("secureboot-hardened-O2-rv32", "forged", 9),
    ("secureboot-hardened-Os-rv32", "forged", 6),
    ("secureboot-base-O2-rv32", "forged", None),
]

BASELINE_MIN = {("secureboot-base-O2-rv32", "forged"): 18}


def main() -> int:
    # Skip rather than crash where the RV32 toolchain was never installed: a
    # machine with only arm-none-eabi-gcc should still be able to run the rest
    # of the suite and get a usable answer.
    if not (FW / "secureboot-hardened-O2-rv32" / "fw.elf").exists():
        print("no RV32 builds (run `make build-rv32`, needs "
              "riscv64-unknown-elf-gcc) — skipping")
        return 0

    vecs = {v.name: v for v in boot_vectors()}
    failures = []

    for build, vec_name, ceiling in CASES:
        bd = str(FW / build)
        vec = vecs[vec_name]
        glen, _, _ = golden_length(bd, vec)
        fs = single_fault_sweep(range(0, glen), models=(FaultModel.SKIP,),
                                skip_widths=(1, 2, 3, 4))
        r = run_campaign(bd, vec, "boot", fs, workers=4)
        expl = r.exploitable()
        n = len(expl)

        # Bug 5's discipline, enforced rather than remembered: an exploitable
        # result whose verdict is not ACCEPT is a classifier artifact, and the
        # whole point of that bug is that it looked like a real finding.
        bogus = [e for e in expl if e.verdict != V_BOOT_ACCEPT]
        status = "ok"
        if bogus:
            status = f"FAIL ({len(bogus)} not verdict-confirmed)"
            failures.append((build, vec_name, n,
                             f"{len(bogus)} exploitable rows have verdict != ACCEPT"))

        floor = BASELINE_MIN.get((build, vec_name))
        if ceiling is not None and n > ceiling:
            status = f"FAIL (> {ceiling})"
            failures.append((build, vec_name, n, f"exceeds ceiling {ceiling}"))
        if floor is not None and n < floor:
            status = f"FAIL (< {floor})"
            failures.append((build, vec_name, n,
                             f"below floor {floor} — harness may have stopped detecting"))
        print(f"  {build:30s} {vec_name:10s} bypasses={n:4d}  {status}")

    if failures:
        print("\nRV32 REGRESSION GATE FAILED")
        for b, v, n, why in failures:
            print(f"  {b} / {v}: {n} — {why}")
        return 1
    print("\nrv32 regression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
