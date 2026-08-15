"""Fault descriptors: the unit of work for a campaign.

Triggering is on INSTRUCTION COUNT, never on PC. Counts are deterministic and
totally ordered; a PC is ambiguous the moment it appears inside a loop. This is
the single most important design decision in the harness -- it is what makes a
campaign reproducible and what makes multi-fault tuples well-defined.

Consequence to state plainly in the writeup: instruction-count triggering gives
zero credit to random-delay countermeasures, because the emulator's clock is not
the attacker's clock. That is a real limitation of simulation, not an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Sequence
import itertools


class FaultModel(IntEnum):
    SKIP = 0        # skip k consecutive instructions
    REG_XOR = 1     # XOR a mask into a register
    REG_SET = 2     # force a register to a fixed value
    MEM_XOR = 3     # XOR a mask into a word in RAM or flash
    OPCODE_XOR = 4  # corrupt the fetched instruction word itself


class Outcome(IntEnum):
    """Six classes. The last two are the ones that colour the heatmap red."""
    OK = 0
    CRASH = 1               # hard fault, invalid instruction, bad access
    HANG = 2                # exceeded instruction budget
    SDC = 3                 # completed, but output diverges from golden
    SEC_BYPASS = 4          # unsigned or rolled-back image accepted
    SAFETY_VIOLATION = 5    # nonzero duty with fault condition asserted


@dataclass(frozen=True, slots=True)
class Fault:
    """A single primitive fault. Immutable so tuples of these can be hashed
    and deduplicated across the search."""
    trigger: int                 # instruction index, 0-based from reset
    model: FaultModel
    target: int = 0              # register number, or address for MEM_XOR
    value: int = 0               # mask, replacement value, or skip count k
    width: int = 4               # bytes, for MEM_XOR

    def key(self) -> tuple:
        return (self.trigger, int(self.model), self.target, self.value, self.width)


@dataclass(frozen=True, slots=True)
class FaultSet:
    """One experiment: 1..N primitive faults applied in a single run.

    Sorted on construction so that {A,B} and {B,A} are the same experiment and
    the deduplicator sees them as one. Order of application is trigger order,
    which is the only order that is physically meaningful.
    """
    faults: tuple[Fault, ...]

    def __post_init__(self):
        object.__setattr__(self, "faults", tuple(sorted(self.faults, key=lambda f: f.key())))

    @property
    def order(self) -> int:
        return len(self.faults)

    @property
    def first_trigger(self) -> int:
        return self.faults[0].trigger

    def key(self) -> tuple:
        return tuple(f.key() for f in self.faults)


# ---------------------------------------------------------------------------
# Campaign generation
# ---------------------------------------------------------------------------

def single_fault_sweep(
    trigger_range: range,
    models: Sequence[FaultModel] = (FaultModel.SKIP,),
    skip_widths: Sequence[int] = (1, 2, 3, 4),
    registers: Sequence[int] = tuple(range(16)),
    bit_positions: Sequence[int] = tuple(range(32)),
) -> list[FaultSet]:
    """Exhaustive single-fault sweep. Tractable: this is your week-two milestone.

    Size is |triggers| x (|skip_widths| + |registers| x |bits|) for the default
    model set, so bound trigger_range to the region of interest rather than the
    whole trace -- Ed25519 verify alone is ~10-20M instructions and you do not
    want to fault every one of them.
    """
    out: list[FaultSet] = []
    for t in trigger_range:
        if FaultModel.SKIP in models:
            for k in skip_widths:
                out.append(FaultSet((Fault(t, FaultModel.SKIP, value=k),)))
        if FaultModel.REG_XOR in models:
            for r in registers:
                for b in bit_positions:
                    out.append(FaultSet((Fault(t, FaultModel.REG_XOR, target=r, value=1 << b),)))
    return out


def multi_fault_stream_from_candidates(
    candidates: Sequence[Fault],
    order: int = 2,
    min_separation: int = 1,
):
    """Generator version of multi_fault_from_candidates() -- yields one
    FaultSet at a time instead of building the full list.

    Still narrow the candidates first; this doesn't change the combinatorics,
    it just stops the *combination list itself* from being the thing that runs
    out of memory. A few thousand slice.py candidates already produce tens of
    millions of order-2 pairs -- materializing that many FaultSet objects
    before running any of them is its own way to exhaust memory, separate from
    and in addition to the |trace|^2 problem this function's sibling warns
    about. Feed this to campaign.py's run_campaign_streaming(), which consumes
    it lazily via Pool.imap_unordered() and never holds the full set either.
    """
    for combo in itertools.combinations(candidates, order):
        trigs = sorted(f.trigger for f in combo)
        if all(b - a >= min_separation for a, b in zip(trigs, trigs[1:])):
            yield FaultSet(tuple(combo))


def multi_fault_from_candidates(
    candidates: Sequence[Fault],
    order: int = 2,
    min_separation: int = 1,
) -> list[FaultSet]:
    """Combinations drawn from a PRE-NARROWED candidate list.

    Never call this on the full trace. |trace|^2 is intractable and |trace|^3 is
    absurd -- this is why the taint-narrowing pass in slice.py exists. Feed it
    only instructions the backward slice says can influence the decision, plus
    the near-miss sites the single-fault sweep already flagged.

    min_separation rejects tuples too close together in time to be physically
    realisable by a real glitcher, which keeps the search honest about what an
    attacker can actually do.

    This materializes the full combination list, which is itself a memory
    problem once the candidate set gets into the thousands -- see
    multi_fault_stream_from_candidates() for a generator that doesn't.
    """
    return list(multi_fault_stream_from_candidates(candidates, order, min_separation))


def dedupe(sets: Sequence[FaultSet]) -> list[FaultSet]:
    seen: set[tuple] = set()
    out: list[FaultSet] = []
    for fs in sets:
        k = fs.key()
        if k not in seen:
            seen.add(k)
            out.append(fs)
    return out
