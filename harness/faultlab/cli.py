"""Campaign CLI.

  python -m faultlab.cli sweep   --build ../firmware/build/secureboot-base-O2 --vector forged
  python -m faultlab.cli matrix  --out ../analysis/results
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .campaign import run_campaign, golden_length
from .faults import single_fault_sweep, FaultModel, Outcome
from .target import boot_vectors, supervisor_vectors
from . import store

FIRMWARE = Path(__file__).resolve().parents[2] / "firmware" / "build"


def _sweep(build: str, vec, kind: str, workers: int):
    glen, _, _ = golden_length(build, vec)
    fs = single_fault_sweep(range(0, glen), models=(FaultModel.SKIP,),
                            skip_widths=(1, 2, 3, 4))
    return run_campaign(build, vec, kind, fs, workers=workers), glen, len(fs)


def main() -> None:
    ap = argparse.ArgumentParser(prog="faultlab")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sweep"); s.add_argument("--build", required=True)
    s.add_argument("--vector", default="forged"); s.add_argument("--workers", type=int, default=0)
    m = sub.add_parser("matrix"); m.add_argument("--out", default="../analysis/results")
    m.add_argument("--workers", type=int, default=0)
    a = ap.parse_args()
    w = a.workers or None

    if a.cmd == "sweep":
        vec = {v.name: v for v in boot_vectors()}[a.vector]
        r, glen, n = _sweep(a.build, vec, "boot", w)
        print(f"golden={glen} runs={n} rate={r.rate:,.0f}/s")
        print(r.counts())
        return

    hdr = f"{'build':30s} {'vector':10s} {'golden':>7s} {'runs':>7s} {'BYPASS':>7s} {'rate/s':>9s}"
    print(hdr); print("-" * len(hdr))
    for opt in ("-O0", "-O2", "-Os"):
        for variant in ("base", "hardened"):
            bd = FIRMWARE / f"secureboot-{variant}{opt}"
            for vec in boot_vectors():
                if vec.name == "genuine":
                    continue
                r, glen, n = _sweep(str(bd), vec, "boot", w)
                store.write(r.rows, a.out)
                print(f"{bd.name:30s} {vec.name:10s} {glen:7d} {n:7d} "
                      f"{r.counts()['SEC_BYPASS']:7d} {r.rate:9,.0f}")
            bd = FIRMWARE / f"supervisor-{variant}{opt}"
            for vec in supervisor_vectors():
                if not vec.fault_asserted:
                    continue
                glen, _, _ = golden_length(str(bd), vec)
                fs = single_fault_sweep(range(0, glen), models=(FaultModel.SKIP,),
                                        skip_widths=(1, 2, 3, 4))
                r = run_campaign(str(bd), vec, "supervisor", fs, workers=w)
                store.write(r.rows, a.out)
                print(f"{bd.name:30s} {vec.name:10s} {glen:7d} {len(fs):7d} "
                      f"{r.counts()['SAFETY_VIOLATION']:7d} {r.rate:9,.0f}")


if __name__ == "__main__":
    main()
