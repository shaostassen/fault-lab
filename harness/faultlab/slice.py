"""Backward taint slicing: narrow the trigger space before multi-fault search.

THE PROBLEM. `multi_fault_from_candidates()` in faults.py is explicit that it
must never be called on the full trace -- |trace|^2 combinations is already
intractable at a few thousand instructions, and |trace|^3 is absurd. This
module produces the candidate list it needs: instructions that can actually
influence the accept/reject decision, not every instruction that happens to
execute before it.

WHY DATAFLOW ALONE IS NOT ENOUGH. The naive approach is a classic Weiser
dynamic slice: walk the golden trace backward from the decision, tracking which
registers and memory locations the decision's value depends on. That works for
value-dependent decisions, but the decision this firmware makes is not "what
value ends up in a register" -- `FW_VERDICT_BOOT_ACCEPT` is a compile-time
constant, not a computed one. The decision is "does execution REACH the store
of that constant at all," which is a control-flow question, not a dataflow one.
A pure dataflow slice from the verdict store would find almost nothing.

THE FIX. Every conditional branch executed on the golden path is, by
construction, control-relevant: flipping any one of them changes which side of
the decision tree gets executed, which is exactly the mechanism a skip fault
exploits. So the slice seeds on two things at once and propagates both through
one backward walk:

  1. The memory location(s) the firmware's verdict is written to (classic
     dataflow seed -- kept for generality, in case some other target's
     decision genuinely is value-dependent).
  2. Every conditional branch instruction on the golden path (control-flow
     seed). Capstone does not report the implicit CPSR read a conditional
     branch has on the flags set by the preceding compare -- see
     `_trace_deps_in_child` -- so that dependency is added by hand from the
     instruction's condition code. Once CPSR is tracked as an ordinary
     dataflow value, the compare (or other flag-setting instruction) feeding
     each branch is pulled into the slice automatically by the same backward
     walk, with no separate control-dependence pass required.

LIMITATION, stated plainly rather than hidden: this cannot distinguish a
security-relevant branch from a fixed-trip-count loop back-edge (SHA-256's
compress rounds, memcmp_ct's byte loop) by looking at a single instruction in
isolation -- both are just conditional branches on the golden trace. Address
direction does not separate them either: this codebase's shared reject
epilogues sit at a LOWER address than most of the checks that jump to them
(see RESULTS.md's -O2 survivor writeup), so "backward branch" does not mean
"loop." What does distinguish them is REPETITION COUNT: a bounded loop's
branch instruction executes at its static PC dozens of times per golden run
(SHA-256's compress round, memcmp_ct's byte compare); a decision branch
executes at its static PC once or twice. `backward_slice()` therefore only
auto-seeds a conditional branch on control-flow grounds if its static PC
repeats at most `loop_repeat_threshold` times in the whole trace -- a
heuristic, not a proof, so it is a knob, not a hardcoded constant. A branch
above the threshold can still enter the slice the ordinary way, via dataflow,
if something downstream of it genuinely depends on a register or memory
location it writes.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import multiprocessing as mp

import capstone
from capstone.arm_const import ARM_CC_AL, ARM_CC_INVALID
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_PC

from .backend.unicorn_backend import UnicornBackend
from .faults import Fault, FaultModel
from .target import Target

# See campaign.py's fork-safety note: workers are spawned, never forked, and
# the parent must never hold a Uc. Tracing here follows the same pattern as
# golden_length() -- the emulator lives entirely inside a throwaway child.
_CTX = mp.get_context("spawn")

# Offsets into oracle_state_t (common/oracle.h), matching ORACLE_STATE_FMT
# "<8I" and OracleState's field order in target.py.
_ORACLE_OFFSET = {
    "magic": 0, "verdict": 4, "marks": 8, "cfi_counter": 12,
    "sup_state": 16, "pwm_duty": 20, "image_version": 24, "reserved": 28,
}


@dataclass(slots=True)
class Step:
    pc: int
    cond: bool               # conditionally executed/branching (cc != AL)
    reg_r: frozenset
    reg_w: frozenset
    mem_r: frozenset
    mem_w: frozenset


def _trace_deps_in_child(args):
    """Traced run recording per-instruction register/memory/flag dependencies.

    Same cost class as UnicornBackend.trace(): a one-off analysis run, never
    part of the campaign loop. Capstone detail mode plus two extra hooks make
    this markedly slower per instruction than trace()'s bare PC log, which is
    fine for a few thousand to tens of thousands of instructions and would not
    be fine per campaign run."""
    build_dir, vec, budget = args
    t = Target.load(build_dir)
    be = UnicornBackend(t)
    be.reset(vec.writes(t))

    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md.detail = True

    steps: list[dict] = []

    def on_code(uc, address, size, ud):
        code = bytes(uc.mem_read(address, min(size, 4)))
        insns = list(md.disasm(code, address))
        reg_r: set = set()
        reg_w: set = set()
        cond = False
        if insns:
            insn = insns[0]
            ids_r, ids_w = insn.regs_access()
            reg_r = {insn.reg_name(r) for r in ids_r}
            reg_w = {insn.reg_name(r) for r in ids_w}
            if insn.cc not in (ARM_CC_AL, ARM_CC_INVALID):
                cond = True
                reg_r.add("cpsr")  # capstone under-reports this; see module docstring
        steps.append({"pc": address, "cond": cond, "reg_r": reg_r, "reg_w": reg_w,
                     "mem_r": set(), "mem_w": set()})

    def on_mem(uc, access, address, size, value, ud):
        if not steps:
            return
        cur = steps[-1]
        (cur["mem_w"] if access == UC_MEM_WRITE else cur["mem_r"]).add(address)

    hc = be.uc.hook_add(UC_HOOK_CODE, on_code)
    hm = be.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_mem)
    try:
        be.uc.emu_start(be.uc.reg_read(UC_ARM_REG_PC) | 1,
                        0xFFFFFFF0, timeout=0, count=budget)
    finally:
        be.uc.hook_del(hc)
        be.uc.hook_del(hm)

    return [(s["pc"], s["cond"], frozenset(s["reg_r"]), frozenset(s["reg_w"]),
             frozenset(s["mem_r"]), frozenset(s["mem_w"])) for s in steps]


def trace_deps(build_dir: str, vec, budget: int = 50_000_000) -> list[Step]:
    """Traced golden run with full register/memory/flag dependency info,
    executed in a throwaway child process (see _CTX note above)."""
    with _CTX.Pool(1) as p:
        raw = p.apply(_trace_deps_in_child, ((build_dir, vec, budget),))
    return [Step(pc, cond, rr, rw, mr, mw) for pc, cond, rr, rw, mr, mw in raw]


def backward_slice(steps: list[Step], seed_mem_addrs,
                   loop_repeat_threshold: int = 4) -> list[int]:
    """Dynamic backward slice over an already-traced golden run.

    Returns instruction-count trigger indices (0-based, matching Fault.trigger)
    in ascending order: the candidate set for multi_fault_from_candidates(),
    narrowed from the full trace to instructions that can influence whichever
    memory locations are seeded, directly (dataflow) or via a conditional
    branch on the path to them (control flow -- see module docstring, and its
    note on why `loop_repeat_threshold` exists)."""
    pc_counts = Counter(s.pc for s in steps)
    live = {("mem", a) for a in seed_mem_addrs}
    idx: list[int] = []
    for i in range(len(steps) - 1, -1, -1):
        s = steps[i]
        defs = {("reg", r) for r in s.reg_w} | {("mem", a) for a in s.mem_w}
        auto_control = s.cond and pc_counts[s.pc] <= loop_repeat_threshold
        if auto_control or (defs & live):
            idx.append(i)
            live -= defs
            live |= {("reg", r) for r in s.reg_r} | {("mem", a) for a in s.mem_r}
    idx.reverse()
    return idx


def boot_decision_slice(build_dir: str, vec, budget: int = 50_000_000,
                        loop_repeat_threshold: int = 4) -> list[int]:
    """Candidates for the boot accept/reject decision: verdict and marks,
    the two fields classify_boot() reads to decide `accepted` (classify.py)."""
    t = Target.load(build_dir)
    oracle = t.sym("g_oracle")
    seeds = {oracle + _ORACLE_OFFSET["verdict"], oracle + _ORACLE_OFFSET["marks"]}
    return backward_slice(trace_deps(build_dir, vec, budget), seeds, loop_repeat_threshold)


def supervisor_decision_slice(build_dir: str, vec, budget: int = 50_000_000,
                              loop_repeat_threshold: int = 4) -> list[int]:
    """Candidates for the safety decision: marks, sup_state, pwm_duty, the
    fields classify_supervisor() reads for the fail-closed invariant."""
    t = Target.load(build_dir)
    oracle = t.sym("g_oracle")
    seeds = {oracle + _ORACLE_OFFSET["marks"], oracle + _ORACLE_OFFSET["sup_state"],
             oracle + _ORACLE_OFFSET["pwm_duty"]}
    return backward_slice(trace_deps(build_dir, vec, budget), seeds, loop_repeat_threshold)


def as_skip_faults(trigger_indices, widths=(1, 2, 3, 4)) -> list[Fault]:
    """Expand a candidate trigger list into single-fault SKIP descriptors,
    ready for multi_fault_from_candidates()."""
    return [Fault(t, FaultModel.SKIP, value=k) for t in trigger_indices for k in widths]
