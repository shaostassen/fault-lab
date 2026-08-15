"""Security regression gate.

This is the CI-facing test and the one that makes the project a *process*
rather than a one-off experiment: a code change that reopens a closed bypass
fails the build. That is the phrase that lands with anyone who has been through
a design-history-file audit — security regression testing in the pipeline, not
a report someone wrote once.

Thresholds are ceilings, not exact matches. A change that reduces bypasses
should pass; one that increases them should not. Exact-match assertions would
make every legitimate improvement a red build, which trains people to ignore
the gate.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faultlab.campaign import run_campaign, golden_length
from faultlab.faults import FaultModel, single_fault_sweep
from faultlab.target import boot_vectors

FW = Path(__file__).resolve().parents[2] / "firmware" / "build"

# (build, vector, max_allowed_bypasses)
#
# Hardened -O2 rollback and bad_magic are at ZERO and must stay there: those
# are fully closed, and reopening either means a countermeasure was removed or
# the optimiser folded one. Baseline ceilings are set slightly above measured
# so that unrelated codegen churn does not produce false alarms.
CASES = [
    ("secureboot-hardened-O2", "rollback",  0),
    ("secureboot-hardened-O2", "bad_magic", 0),
    ("secureboot-hardened-O2", "forged",    4),
    ("secureboot-hardened-Os", "bad_magic", 0),
    ("secureboot-hardened-Os", "forged",    5),
    # Baseline is deliberately vulnerable. Asserting a FLOOR here catches the
    # opposite failure: a harness change that stops finding real bypasses.
    # A gate that only checks "few enough" passes trivially when broken.
    ("secureboot-base-O2",     "forged",    None),
]

BASELINE_MIN = {("secureboot-base-O2", "forged"): 20}


def main() -> int:
    vecs = {v.name: v for v in boot_vectors()}
    failures = []

    for build, vec_name, ceiling in CASES:
        bd = str(FW / build)
        vec = vecs[vec_name]
        glen, _, _ = golden_length(bd, vec)
        fs = single_fault_sweep(range(0, glen), models=(FaultModel.SKIP,),
                                skip_widths=(1, 2, 3, 4))
        r = run_campaign(bd, vec, "boot", fs, workers=4)
        n = len(r.exploitable())

        floor = BASELINE_MIN.get((build, vec_name))
        status = "ok"
        if ceiling is not None and n > ceiling:
            status = f"FAIL (> {ceiling})"
            failures.append((build, vec_name, n, f"exceeds ceiling {ceiling}"))
        if floor is not None and n < floor:
            status = f"FAIL (< {floor})"
            failures.append((build, vec_name, n, f"below floor {floor} — "
                                                 "harness may have stopped detecting"))
        print(f"  {build:26s} {vec_name:10s} bypasses={n:4d}  {status}")

    if failures:
        print("\nREGRESSION GATE FAILED")
        for b, v, n, why in failures:
            print(f"  {b} / {v}: {n} — {why}")
        return 1
    print("\nregression gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
