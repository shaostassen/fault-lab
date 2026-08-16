"""Campaign orchestration.

Structure of a campaign:

  golden run (traced, once)  ->  ladder (16 rungs)  ->  N faulted runs

Parallelism is process-based, not thread-based: Unicorn instances hold C state
and the GIL would serialise the emulation anyway. Each worker builds its OWN
backend and its OWN ladder in an initializer, so nothing crosses a process
boundary per work item except a small fault descriptor and a small result.

MEASURED SCALING CAVEAT worth reporting in the writeup: at high worker counts
this becomes memory-bandwidth-bound on the snapshot restore memcpy, not
compute-bound. 128KB of RAM copied per run, times tens of thousands of runs
per second, saturates before the core count does. Report where the knee is
rather than claiming linear scaling.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, asdict
import multiprocessing as mp
from pathlib import Path

from .backend.unicorn_backend import UnicornBackend, HaltReason
from .classify import classify_boot, classify_supervisor
from .faults import Outcome, FaultSet, FaultModel
from .target import Target, BootVector, SupervisorVector

HANG_MULTIPLIER = 3  # budget = 3x golden length; a tunable that CHANGES RESULTS,
                     # so it belongs in campaign metadata, not buried in a constant


@dataclass(slots=True)
class Row:
    """One campaign result. Flat and primitive-typed so it serialises cheaply
    across the process boundary and lands in Parquet without transformation."""
    build: str
    vector: str
    order: int
    trigger: int
    pc: int
    model: int
    target_reg: int
    value: int
    outcome: int
    instructions: int
    verdict: int
    marks: int
    halt_reason: int      # HaltReason: was this a clean oracle halt, or did
                          # the CPU crash/hang? Distinguishes "software chose
                          # wrong" from "software stopped responding" -- see
                          # the watchdog-model analysis in RESULTS.md, which a
                          # SAFETY_VIOLATION outcome alone can't distinguish.
    triggers: str        # comma-joined, for multi-fault tuples
    values: str          # comma-joined widths/masks, parallel to `triggers`.
                         # `value` above is only fault 0's, which makes a
                         # multi-fault Row impossible to replay from storage --
                         # reconstructing a triple with the first fault's width
                         # for all three silently runs a DIFFERENT experiment,
                         # and looks like a failure to reproduce.


# --- worker state -----------------------------------------------------------
_W = {}


def _init_worker(build_dir: str, vec, kind: str, golden_len: int, rungs: int):
    t = Target.load(build_dir)
    be = UnicornBackend(t)
    writes = vec.writes(t)
    be.reset(writes)
    golden, _ = be.trace(golden_len * HANG_MULTIPLIER)
    ladder = be.build_ladder(writes, golden_len, rungs)
    _W.update(backend=be, writes=writes, vec=vec, kind=kind,
              golden=golden, ladder=ladder, budget=golden_len * HANG_MULTIPLIER,
              build=Path(build_dir).name)


def _run_one(fs: FaultSet) -> Row:
    be = _W["backend"]
    rung = be.nearest_rung(_W["ladder"], fs.first_trigger)
    res = be.run(_W["budget"], faults=fs, resume=rung)
    if _W["kind"] == "boot":
        oc = classify_boot(res, _W["vec"], _W["golden"])
    else:
        oc = classify_supervisor(res, _W["vec"], _W["golden"])
    f0 = fs.faults[0]
    return Row(
        build=_W["build"], vector=_W["vec"].name, order=fs.order,
        trigger=f0.trigger, pc=res.final_pc, model=int(f0.model),
        target_reg=f0.target, value=f0.value, outcome=int(oc),
        instructions=res.instructions, verdict=res.oracle.verdict,
        marks=res.oracle.marks, halt_reason=int(res.halt_reason),
        triggers=",".join(str(f.trigger) for f in fs.faults),
        values=",".join(str(f.value) for f in fs.faults),
    )


@dataclass(slots=True)
class CampaignResult:
    rows: list
    golden_length: int
    elapsed: float
    rate: float

    def counts(self) -> dict:
        c = {o.name: 0 for o in Outcome}
        for r in self.rows:
            c[Outcome(r.outcome).name] += 1
        return c

    def exploitable(self) -> list:
        return [r for r in self.rows
                if r.outcome in (Outcome.SEC_BYPASS, Outcome.SAFETY_VIOLATION)]


# --- fork safety ------------------------------------------------------------
#
# WORKERS MUST BE SPAWNED, NEVER FORKED.
#
# This is a correctness requirement, not a style preference, and it cost a real
# debugging session. Unicorn wraps QEMU's TCG, which keeps a translation cache
# and other C-level global state. multiprocessing's default start method on
# Linux is fork(), which copies that state into every child -- and merely
# having `import unicorn` executed in the parent is enough, whether or not a Uc
# object is alive.
#
# Observed failure: the identical campaign (same binary, same fault set, same
# process) returned 4 exploitable sites on eleven runs and 24 on the twelfth.
# With workers=1 it was always 4. An intermittent, silent, result-inflating
# corruption is close to the worst failure mode a security harness can have --
# it manufactures findings rather than hiding them, and a fabricated bypass
# survives review far longer than a missing one.
#
# Two fixes, both applied:
#   1. mp.get_context("spawn") -- children start from a fresh interpreter, so
#      there is no inherited emulator state to corrupt.
#   2. golden_length() does its emulation in a throwaway child, so the parent
#      never holds a Uc even under a start method that would tolerate it.
#
# Cost: spawn re-imports the module per worker, so pool startup is slower.
# That is a few hundred milliseconds against a result you can trust.

_CTX = mp.get_context("spawn")

def _golden_in_child(args):
    build_dir, vec = args
    t = Target.load(build_dir)
    be = UnicornBackend(t)
    be.reset(vec.writes(t))
    res, seq = be.trace(50_000_000)
    return len(seq), list(seq)


def golden_length(build_dir: str, vec) -> tuple[int, object, list]:
    """Traced reference run, executed in a throwaway child process.

    Returns (instruction count, None, PC sequence). The result object is not
    returned because it would have to cross a process boundary; callers that
    need it should ask a worker."""
    with _CTX.Pool(1) as p:
        n, seq = p.apply(_golden_in_child, ((build_dir, vec),))
    return n, None, seq


def run_campaign(build_dir: str, vec, kind: str, fault_sets: list,
                 workers: int = None, rungs: int = 16,
                 chunksize: int = 256) -> CampaignResult:
    glen, _, _ = golden_length(build_dir, vec)
    workers = workers or os.cpu_count() or 1
    t0 = time.perf_counter()
    if workers == 1:
        _init_worker(build_dir, vec, kind, glen, rungs)
        rows = [_run_one(fs) for fs in fault_sets]
    else:
        with _CTX.Pool(workers, initializer=_init_worker,
                       initargs=(build_dir, vec, kind, glen, rungs)) as p:
            rows = p.map(_run_one, fault_sets, chunksize=chunksize)
    el = time.perf_counter() - t0
    return CampaignResult(rows, glen, el, len(fault_sets) / el if el else 0.0)


@dataclass(slots=True)
class StreamingCampaignResult:
    """Same shape of answer as CampaignResult, for a candidate set too large to
    materialize. Keeps only aggregate counts and the exploitable rows, not
    every row -- see run_campaign_streaming()."""
    total: int
    counts: dict
    exploitable: list
    golden_length: int
    elapsed: float
    rate: float


def run_campaign_streaming(build_dir: str, vec, kind: str, fault_sets_iter,
                           workers: int = None, rungs: int = 16,
                           chunksize: int = 2000) -> StreamingCampaignResult:
    """Like run_campaign(), but drives Pool.imap_unordered() over a lazily
    consumed iterable instead of collecting every Row into a list.

    run_campaign() holds the full input list AND the full output list in
    memory at once, which is fine at thousands of fault sets and is not fine
    at tens of millions -- multi_fault_from_candidates() on a few thousand
    slice.py candidates already produces that many pairs. Pass a generator
    (e.g. combinations() filtered by min_separation, built the same way
    multi_fault_from_candidates() does internally but never materialized) and
    memory stays flat regardless of how many pairs run, because only the
    exploitable rows are kept in full."""
    glen, _, _ = golden_length(build_dir, vec)
    workers = workers or os.cpu_count() or 1
    t0 = time.perf_counter()
    counts = {o.name: 0 for o in Outcome}
    exploitable: list[Row] = []
    total = 0
    with _CTX.Pool(workers, initializer=_init_worker,
                   initargs=(build_dir, vec, kind, glen, rungs)) as p:
        for row in p.imap_unordered(_run_one, fault_sets_iter, chunksize=chunksize):
            total += 1
            counts[Outcome(row.outcome).name] += 1
            if row.outcome in (Outcome.SEC_BYPASS, Outcome.SAFETY_VIOLATION):
                exploitable.append(row)
    el = time.perf_counter() - t0
    return StreamingCampaignResult(total, counts, exploitable, glen, el,
                                   total / el if el else 0.0)
