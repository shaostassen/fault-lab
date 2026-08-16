"""Export campaign results for the web case study.

The standalone `heatmap.py` artifact ships every instruction at full
resolution, which is right for a local tool and wrong for a page with a
performance budget: the RV32 hardened trace alone is 12,430 columns, and at a
realistic render width that is ten instructions per pixel. Nobody can see a
column, so shipping them costs bytes and buys nothing.

This exports the same campaigns bucketed to a fixed column count, with the
**most severe** outcome winning each bucket. Two consequences worth being
explicit about, because they are the difference between compression and
distortion:

  * Severity-max means a single exploitable instruction cannot be averaged
    away by the 40 harmless ones sharing its bucket. On a plot whose whole
    subject is rare critical events, that is the only defensible reduction --
    a mean or a mode would hide exactly what the reader is looking for.
  * It systematically OVER-states how much of the trace is dangerous, since
    one red instruction paints a whole bucket red. The component says so, and
    the exact counts ship alongside so the real numbers are never inferred
    from pixels.

Encoding is a digit string per skip width -- one character per bucket, the
outcome code -- because it is compact, diffable, and reviewable in a way a
base64 typed array is not.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness"))

from elftools.elf.elffile import ELFFile

from faultlab.campaign import golden_length, run_campaign
from faultlab.faults import FaultModel, Outcome, single_fault_sweep
from faultlab.target import Target, boot_vectors
from faultlab.backend.unicorn_backend import UnicornBackend

FW = Path(__file__).resolve().parents[1] / "firmware" / "build"
BUCKETS = 512          # ~2x a realistic render width; more is invisible
WIDTHS = (1, 2, 3, 4)
ISAS = ("cm3", "rv32")
VARIANTS = ("base", "hardened")
VECTORS = ("forged", "rollback")

# Severity order: later wins a bucket. OK is the floor, exploitable the ceiling.
SEVERITY = {int(Outcome.OK): 0, int(Outcome.SDC): 1, int(Outcome.HANG): 2,
            int(Outcome.CRASH): 3, int(Outcome.SAFETY_VIOLATION): 4,
            int(Outcome.SEC_BYPASS): 5}


def fns_of(bd):
    out = []
    with open(f"{bd}/fw.elf", "rb") as fh:
        for s in ELFFile(fh).get_section_by_name(".symtab").iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s.name:
                out.append((s["st_value"] & ~1, max(s["st_size"], 2), s.name))
    return sorted(out)


def whichfn(f, pc):
    for a, sz, n in f:
        if a <= pc < a + sz:
            return n
    return "?"


def collect(isa, variant, vector_name, opt="-O2"):
    suffix = "" if isa == "cm3" else f"-{isa}"
    bd = str(FW / f"secureboot-{variant}{opt}{suffix}")
    vec = {v.name: v for v in boot_vectors()}[vector_name]
    glen, _, _ = golden_length(bd, vec)

    t = Target.load(bd)
    be = UnicornBackend(t)
    be.reset(vec.writes(t))
    _, seq = be.trace(glen * 3)
    funcs = fns_of(bd)

    fs = single_fault_sweep(range(0, glen), models=(FaultModel.SKIP,),
                            skip_widths=WIDTHS)
    r = run_campaign(bd, vec, "boot", fs, workers=8)

    nb = min(BUCKETS, glen)
    rows = {k: [int(Outcome.OK)] * nb for k in WIDTHS}
    for row in r.rows:
        b = row.trigger * nb // glen
        cur = rows[row.value][b]
        if SEVERITY[row.outcome] > SEVERITY[cur]:
            rows[row.value][b] = row.outcome

    # One function label per bucket, taken at the bucket's first instruction.
    fn_names, fn_idx, fn_per_bucket = [], {}, []
    for b in range(nb):
        pc = seq[b * glen // nb] if b * glen // nb < len(seq) else 0
        name = whichfn(funcs, pc)
        if name not in fn_idx:
            fn_idx[name] = len(fn_names)
            fn_names.append(name)
        fn_per_bucket.append(fn_idx[name])

    # Run-length encode the labels: a trace stays inside a function for many
    # consecutive buckets, so the raw array is almost all repeats.
    runs = []
    for v in fn_per_bucket:
        if runs and runs[-1][0] == v:
            runs[-1][1] += 1
        else:
            runs.append([v, 1])

    return {
        "isa": isa, "variant": variant, "vector": vector_name,
        "golden": glen, "buckets": nb, "total": len(r.rows),
        "counts": r.counts(),
        "exploitable": len(r.exploitable()),
        "rows": {str(k): "".join(str(o) for o in rows[k]) for k in WIDTHS},
        "fns": fn_names,
        "fnRuns": [x for run in runs for x in run],
    }


def main():
    data = {f"{i}|{v}|{vec}": collect(i, v, vec)
            for i in ISAS for v in VARIANTS for vec in VECTORS}
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("faultmap.json")
    out.write_text(json.dumps(data, separators=(",", ":")))
    print(f"wrote {out} ({out.stat().st_size / 1024:.1f} KB)")
    for k, d in data.items():
        print(f"  {k:24s} golden={d['golden']:6d} buckets={d['buckets']:4d} "
              f"exploitable={d['exploitable']:3d}")


if __name__ == "__main__":
    main()
