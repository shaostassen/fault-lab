"""Determinism regression test.

A fault injection harness that returns different answers on different runs is
worse than no harness, because its output looks authoritative. This test is the
gate: same binary, same fault set, varying worker counts, identical exploitable
sets or it fails.

Run it after any change to campaign.py, the backend, or the classifier.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from faultlab.target import boot_vectors
from faultlab.faults import single_fault_sweep, FaultModel
from faultlab.campaign import run_campaign, golden_length

BUILD = "../firmware/build/secureboot-base-O2"


def main() -> int:
    vec = {v.name: v for v in boot_vectors()}["forged"]
    glen, _, _ = golden_length(BUILD, vec)
    fs = single_fault_sweep(range(0, glen), models=(FaultModel.SKIP,),
                            skip_widths=(1, 2, 3, 4))
    sigs = {}
    for workers in (1, 2, 4, 8):
        r = run_campaign(BUILD, vec, "boot", fs, workers=workers)
        sig = tuple(sorted((e.trigger, e.value) for e in r.exploitable()))
        sigs[workers] = sig
        print(f"  workers={workers}  bypasses={len(sig):3d}  "
              f"hash={hash(sig) & 0xFFFFFF:#08x}  rate={r.rate:,.0f}/s")
    distinct = set(sigs.values())
    ok = len(distinct) == 1
    print(f"\ndistinct result sets: {len(distinct)}  ->  "
          f"{'DETERMINISTIC' if ok else 'NONDETERMINISTIC (FAIL)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
