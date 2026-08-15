"""Genetic-algorithm multi-fault search.

WHY THIS EXISTS. faults.py's multi_fault_from_candidates() is explicit that
|trace|^2 is already near the edge of tractable and |trace|^3 is absurd -- a
few thousand slice.py candidates already produce tens of millions of pairs
(see RESULTS.md's double-fault campaign). Order 3 and up is not reachable by
exhaustive or seeded-pairwise search at all: even a modest 1,000-candidate
pool has C(1000,3) ~= 166M triples, and a realistic candidate pool is an
order of magnitude bigger than that. A genetic algorithm trades completeness
for reach -- it can't prove a space is closed the way the double-fault
exhaustive searches did for rollback/bad_magic, but it can find a needle in
a haystack too large to sift by hand.

FITNESS MUST COME FROM THE HARNESS, NOT THE FIRMWARE. classify.py's central
rule -- the firmware reports what it did, the harness owns the judgement --
applies here too. Fitness is computed purely from Row fields the harness
already trusts (outcome, and the oracle marks bitmask, itself only
interpreted after oracle_trustworthy() passes inside classify.py): how many
of the golden run's checkpoint bits a faulted run reached. This is a
smoothed, partial-credit view of the same SDC/near-miss signal
multi_fault_from_candidates() is seeded from in the seeded-search case --
GA needs a *gradient* to climb, not just a pass/fail bit, or mutation and
crossover have nothing to select on.

SEEDING. Per README.md's original plan ("GA search over the residual space,
seeded from single-fault near-misses"), the gene pool this operates over is
NOT the raw trigger range -- it's whatever candidate pool the caller passes
in, typically slice.py's narrowed output unioned with SDC-outcome triggers
from a single-fault sweep. GA explores COMBINATIONS of a pre-narrowed pool,
same as multi_fault_from_candidates(); it does not replace the narrowing.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from .campaign import _CTX, _init_worker, _run_one, golden_length, Row
from .faults import Fault, FaultSet, Outcome
from .target import Target


def _popcount(x: int) -> int:
    return bin(x).count("1")


def fitness(row: Row, golden_marks: int) -> float:
    """1.0 = exploit found. Otherwise, partial credit for how many of the
    golden run's checkpoint bits (marks) a faulted run reached -- SDC gets
    a higher floor than CRASH/HANG because it means the run completed
    without derailing, just landed somewhere other than golden state."""
    if row.outcome in (Outcome.SEC_BYPASS, Outcome.SAFETY_VIOLATION):
        return 1.0
    total = _popcount(golden_marks) or 1
    achieved = _popcount(row.marks & golden_marks) / total
    if row.outcome == Outcome.SDC:
        return 0.5 + 0.4 * achieved
    if row.outcome in (Outcome.CRASH, Outcome.HANG):
        return 0.1 * achieved
    return 0.0  # OK: correctly rejected, indistinguishable from no fault at all


def _golden_marks_in_child(args):
    build_dir, vec = args
    t = Target.load(build_dir)
    from .backend.unicorn_backend import UnicornBackend
    be = UnicornBackend(t)
    be.reset(vec.writes(t))
    res, seq = be.trace(50_000_000)
    return len(seq), res.oracle.marks


def golden_reference(build_dir: str, vec) -> tuple[int, int]:
    """(golden_length, golden_marks), computed in a throwaway child -- same
    fork-safety reasoning as campaign.py's golden_length(): the driving
    process must never hold a Uc before spawning the GA's worker pool."""
    with _CTX.Pool(1) as p:
        return p.apply(_golden_marks_in_child, ((build_dir, vec),))


def _valid(fs_faults: tuple[Fault, ...], min_separation: int) -> bool:
    trigs = sorted(f.trigger for f in fs_faults)
    return all(b - a >= min_separation for a, b in zip(trigs, trigs[1:]))


def _random_individual(pool: list[Fault], order: int, min_separation: int,
                       rng: random.Random, max_tries: int = 50) -> FaultSet:
    for _ in range(max_tries):
        faults = tuple(rng.sample(pool, order))
        if _valid(faults, min_separation):
            return FaultSet(faults)
    # pool too dense for min_separation at this order -- fall back to
    # whatever was last sampled rather than looping forever.
    return FaultSet(faults)


def _mutate(fs: FaultSet, pool: list[Fault], min_separation: int,
           rng: random.Random, max_tries: int = 20) -> FaultSet:
    faults = list(fs.faults)
    i = rng.randrange(len(faults))
    for _ in range(max_tries):
        candidate = list(faults)
        candidate[i] = rng.choice(pool)
        if _valid(tuple(candidate), min_separation):
            return FaultSet(tuple(candidate))
    return fs


def _crossover(a: FaultSet, b: FaultSet, min_separation: int,
               rng: random.Random, max_tries: int = 20) -> FaultSet:
    pool = list({f.key(): f for f in (*a.faults, *b.faults)}.values())
    order = a.order
    for _ in range(max_tries):
        if len(pool) < order:
            break
        faults = tuple(rng.sample(pool, order))
        if _valid(faults, min_separation):
            return FaultSet(faults)
    return a if rng.random() < 0.5 else b


def _tournament(scored: list[tuple[float, FaultSet]], k: int,
                rng: random.Random) -> FaultSet:
    return max(rng.sample(scored, min(k, len(scored))), key=lambda x: x[0])[1]


@dataclass(slots=True)
class GAConfig:
    order: int = 3
    population: int = 500
    generations: int = 30
    mutation_rate: float = 0.3
    elite_frac: float = 0.1
    tournament_size: int = 4
    min_separation: int = 1
    immigrant_frac: float = 0.1  # fresh random individuals per generation,
                                 # against premature convergence on a local
                                 # SDC plateau that isn't actually near an
                                 # exploit -- see RESULTS.md's GA section
    seed: int = 0


@dataclass(slots=True)
class GAResult:
    best_fault_set: FaultSet | None
    best_fitness: float
    best_row: Row | None
    found_exploit: bool
    generations_run: int
    elapsed: float
    history: list = field(default_factory=list)  # (generation, best, mean) per gen


def run_ga(build_dir: str, vec, kind: str, pool: list[Fault],
          config: GAConfig = GAConfig(), workers: int | None = None,
          rungs: int = 16) -> GAResult:
    """Evolve a population of FaultSets of order config.order, using
    fitness() as the selection pressure. Stops early the first generation any
    individual reaches fitness 1.0 (a real exploit), otherwise runs
    config.generations and returns the best found.

    workers=None uses os.cpu_count(); each generation is one campaign batch
    (config.population runs), the population size that dominates cost, not
    the generation count."""
    import os
    workers = workers or os.cpu_count() or 1
    rng = random.Random(config.seed)
    glen, golden_marks = golden_reference(build_dir, vec)

    population = [_random_individual(pool, config.order, config.min_separation, rng)
                 for _ in range(config.population)]

    best_fs, best_fit, best_row = None, -1.0, None
    history = []
    t0 = time.perf_counter()
    elite_n = max(1, int(config.population * config.elite_frac))

    with _CTX.Pool(workers, initializer=_init_worker,
                   initargs=(build_dir, vec, kind, glen, rungs)) as p:
        for gen in range(config.generations):
            rows = p.map(_run_one, population, chunksize=64)
            scored = [(fitness(r, golden_marks), fs, r) for r, fs in zip(rows, population)]
            scored.sort(key=lambda x: x[0], reverse=True)

            gen_best_fit, gen_best_fs, gen_best_row = scored[0]
            if gen_best_fit > best_fit:
                best_fit, best_fs, best_row = gen_best_fit, gen_best_fs, gen_best_row
            mean_fit = sum(s[0] for s in scored) / len(scored)
            history.append((gen, gen_best_fit, mean_fit))

            if best_fit >= 1.0:
                return GAResult(best_fs, best_fit, best_row, True, gen + 1,
                               time.perf_counter() - t0, history)

            elites = [fs for _, fs, _ in scored[:elite_n]]
            ranked = [(f, fs) for f, fs, _ in scored]
            immigrant_n = max(0, int(config.population * config.immigrant_frac))
            next_gen = list(elites)
            next_gen.extend(_random_individual(pool, config.order, config.min_separation, rng)
                            for _ in range(immigrant_n))
            while len(next_gen) < config.population:
                pa = _tournament(ranked, config.tournament_size, rng)
                pb = _tournament(ranked, config.tournament_size, rng)
                child = _crossover(pa, pb, config.min_separation, rng)
                if rng.random() < config.mutation_rate:
                    child = _mutate(child, pool, config.min_separation, rng)
                next_gen.append(child)
            population = next_gen

    return GAResult(best_fs, best_fit, best_row, best_fit >= 1.0,
                    config.generations, time.perf_counter() - t0, history)
