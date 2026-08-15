"""Unicorn execution backend.

THE PERFORMANCE PROBLEM, stated up front because it dictates the design:

A Python UC_HOOK_CODE callback fires once per instruction and costs roughly a
microsecond. Over a campaign of hundreds of thousands of runs that dominates
everything else. Python is not the problem per se -- the per-instruction
callback boundary is.

Three mitigations, applied together:

  1. NO CODE HOOK IN CAMPAIGN RUNS. The trigger is an instruction count, and
     uc.emu_start() takes a count argument, so advancing exactly N instructions
     needs zero Python callbacks. The code hook is used ONLY for the one-off
     golden trace. This is why triggering on instruction count rather than PC
     is load-bearing rather than a stylistic choice.

  2. THE SNAPSHOT LADDER. Restoring from the nearest rung turns an O(T) replay
     per fault into O(T / rungs).

  3. RANGED MMIO HOOK ONLY. The oracle hook is bounded to a 4KB window, so it
     costs nothing on ordinary instructions.

Instances are NOT thread-safe. One per worker, always.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

import capstone
from unicorn import (
    Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
    UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_PROT_ALL,
    UC_PROT_READ, UC_PROT_EXEC, UC_PROT_WRITE, UcError,
)
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_LR

from ..faults import FaultModel, FaultSet
from ..target import (
    Target, OracleState, FLASH_BASE, FLASH_SIZE, RAM_BASE, RAM_SIZE,
    ORACLE_BASE, ORACLE_WINDOW, ORACLE_HALT, ORACLE_MARK, ORACLE_STATE_SIZE,
    ORACLE_MAGIC, ORACLE_STATE_FMT,
)


class HaltReason(IntEnum):
    ORACLE = 0    # firmware wrote a verdict
    BUDGET = 1    # instruction budget exhausted -> HANG
    CPUFAULT = 2  # CPU exception / bad access -> CRASH
    ERROR = 3


@dataclass(slots=True)
class RunResult:
    halt_reason: HaltReason
    instructions: int
    oracle: OracleState
    marks: list
    final_pc: int = 0
    error: str = None


@dataclass(slots=True)
class Snapshot:
    """One rung. CPU context plus a RAM copy -- restore is a memcpy, which is
    microseconds at 128KB. Sixteen rungs is 2MB per worker: trivial, and it
    turns a T-instruction replay into T/16."""
    instr_count: int
    context: object
    ram: bytes


class UnicornBackend:

    def __init__(self, target: Target) -> None:
        self.target = target
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        # FLASH IS READ+EXEC, NEVER WRITE. Two reasons, one correctness and
        # one fidelity:
        #
        # CORRECTNESS: restore() only restores RAM, because copying 256KB of
        # flash per run would dominate the runtime. If flash were writable, a
        # faulted store could corrupt it and that corruption would PERSIST into
        # every subsequent run handled by the same worker. This actually
        # happened: the same campaign returned 4 exploitable sites at 1/2/4
        # workers and 24 at 8 workers, perfectly reproducibly, because changing
        # the worker count changes which corrupting run precedes which other
        # run. Cross-run state leakage is invisible at low parallelism and
        # inflates results at high parallelism.
        #
        # FIDELITY: this is also what the real part does. Cortex-M flash is not
        # writable by a plain store -- it needs a flash controller unlock
        # sequence. A faulted store into flash SHOULD raise a CPU fault, and
        # with this mapping it does, and gets classified CRASH.
        self.uc.mem_map(FLASH_BASE, FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(RAM_BASE, RAM_SIZE, UC_PROT_ALL)
        self.uc.mem_map(ORACLE_BASE, ORACLE_WINDOW, UC_PROT_ALL)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_mmio,
                         begin=ORACLE_BASE, end=ORACLE_BASE + ORACLE_WINDOW)
        self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._oracle_addr = target.sym("g_oracle")
        self._halted = False
        self._marks = []
        self._instr = 0

    # --- oracle ------------------------------------------------------------

    def _on_mmio(self, uc, access, address, size, value, ud):
        if address == ORACLE_HALT:
            self._halted = True
            uc.emu_stop()
        elif address == ORACLE_MARK:
            self._marks.append(value)

    def _read_oracle(self) -> OracleState:
        return OracleState.unpack(
            bytes(self.uc.mem_read(self._oracle_addr, ORACLE_STATE_SIZE)))

    # --- lifecycle ---------------------------------------------------------

    def reset(self, writes) -> None:
        """Full reset plus test-vector injection. `writes` come from the
        vector's .writes(target) -- this is what lets one binary serve every
        input without a rebuild."""
        # Programming flash is a privileged operation the harness performs, not
        # something the emulated CPU can do. Bump permissions only for the load.
        self.uc.mem_protect(FLASH_BASE, FLASH_SIZE, UC_PROT_ALL)
        self.uc.mem_write(FLASH_BASE, self.target.flash)
        self.uc.mem_protect(FLASH_BASE, FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_write(RAM_BASE, b"\x00" * RAM_SIZE)
        self.uc.mem_write(self._oracle_addr,
                          struct.pack(ORACLE_STATE_FMT, ORACLE_MAGIC, 0, 0, 0, 0, 0, 0, 0))
        for addr, data in writes:
            self.uc.mem_write(addr, data)
        self.uc.reg_write(UC_ARM_REG_SP, self.target.initial_sp)
        self.uc.reg_write(UC_ARM_REG_PC, self.target.entry | 1)
        # R0-R12 and LR are DEFINED zero, not left whatever they were. Real
        # Cortex-M3 silicon leaves these architecturally undefined on reset,
        # but "undefined" must mean one deliberate, documented value here, not
        # an accident of call order. _init_worker() calls trace() (a full,
        # unfaulted golden run) before build_ladder() snapshots rung 0 -- if
        # this loop is skipped, rung 0 inherits whatever registers the golden
        # run's FINAL instructions happened to leave behind, not a clean reset
        # state. A trigger=0 fault that skips Reset_Handler's first register
        # load then reads that leftover value instead: found via a trigger=0
        # skip reading golden-trace-tail garbage into r2 and changing how the
        # .data copy loop behaved, producing a SEC_BYPASS that a second,
        # independent run with genuinely undefined (zeroed) registers does
        # not reproduce.
        for r in range(UC_ARM_REG_R0, UC_ARM_REG_R0 + 13):  # R0..R12
            self.uc.reg_write(r, 0)
        self.uc.reg_write(UC_ARM_REG_LR, 0)
        self._halted = False
        self._marks = []
        self._instr = 0

    def snapshot(self) -> Snapshot:
        return Snapshot(self._instr, self.uc.context_save(),
                        bytes(self.uc.mem_read(RAM_BASE, RAM_SIZE)))

    def restore(self, s: Snapshot) -> None:
        self.uc.context_restore(s.context)
        self.uc.mem_write(RAM_BASE, s.ram)
        self._instr = s.instr_count
        self._halted = False
        self._marks = []

    # --- execution ---------------------------------------------------------

    def _advance(self, count: int) -> bool:
        """Run exactly `count` instructions with no Python code hook.
        Returns False if execution halted early. This is the fast path and
        should cover the overwhelming majority of executed instructions."""
        if self._halted:
            return False
        if count <= 0:
            return True
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        self.uc.emu_start(pc | 1, 0xFFFFFFF0, timeout=0, count=count)
        if self._halted:
            return False
        self._instr += count
        return True

    def _skip_bytes(self, pc: int, k: int) -> int:
        """Total width of the next k instructions.

        Thumb-2 is variable width (2 or 4 bytes), so a naive pc += 2*k produces
        misaligned garbage and inflates the CRASH count -- which would look like
        a result and would be wrong. Decode properly."""
        code = bytes(self.uc.mem_read(pc, 4 * k + 8))
        total = 0
        for i, insn in enumerate(self._md.disasm(code, pc)):
            if i >= k:
                break
            total += insn.size
        return total or 2

    def _apply(self, f) -> None:
        uc = self.uc
        if f.model == FaultModel.SKIP:
            pc = uc.reg_read(UC_ARM_REG_PC)
            uc.reg_write(UC_ARM_REG_PC, (pc + self._skip_bytes(pc, f.value)) | 1)
        elif f.model == FaultModel.REG_XOR:
            r = UC_ARM_REG_R0 + f.target
            uc.reg_write(r, (uc.reg_read(r) ^ f.value) & 0xFFFFFFFF)
        elif f.model == FaultModel.REG_SET:
            uc.reg_write(UC_ARM_REG_R0 + f.target, f.value & 0xFFFFFFFF)
        elif f.model == FaultModel.MEM_XOR:
            cur = int.from_bytes(uc.mem_read(f.target, f.width), "little")
            uc.mem_write(f.target, (cur ^ f.value).to_bytes(f.width, "little"))
        elif f.model == FaultModel.OPCODE_XOR:
            pc = uc.reg_read(UC_ARM_REG_PC)
            cur = int.from_bytes(uc.mem_read(pc, 2), "little")
            uc.mem_write(pc, ((cur ^ f.value) & 0xFFFF).to_bytes(2, "little"))

    def run(self, budget: int, faults=None, resume=None) -> RunResult:
        if resume is not None:
            self.restore(resume)
        try:
            if faults is not None:
                for f in faults.faults:
                    if not self._advance(f.trigger - self._instr):
                        break
                    self._apply(f)
            if not self._halted:
                remaining = budget - self._instr
                if remaining > 0:
                    self.uc.emu_start(self.uc.reg_read(UC_ARM_REG_PC) | 1,
                                      0xFFFFFFF0, timeout=0, count=remaining)
                    if not self._halted:
                        self._instr = budget
        except UcError as e:
            return RunResult(HaltReason.CPUFAULT, self._instr, self._read_oracle(),
                             list(self._marks), self.uc.reg_read(UC_ARM_REG_PC), str(e))
        return RunResult(
            HaltReason.ORACLE if self._halted else HaltReason.BUDGET,
            self._instr, self._read_oracle(), list(self._marks),
            self.uc.reg_read(UC_ARM_REG_PC))

    # --- golden trace (the ONLY place a code hook is used) -----------------

    def trace(self, budget: int):
        """One-off traced run recording the full PC sequence.

        Costs ~1us/instruction. Run once per (target, vector), never in the
        campaign loop."""
        seq = []
        h = self.uc.hook_add(UC_HOOK_CODE, lambda u, a, s, d: seq.append(a))
        err = None
        try:
            self.uc.emu_start(self.uc.reg_read(UC_ARM_REG_PC) | 1,
                              0xFFFFFFF0, timeout=0, count=budget)
            reason = HaltReason.ORACLE if self._halted else HaltReason.BUDGET
        except UcError as e:
            reason, err = HaltReason.CPUFAULT, str(e)
        finally:
            self.uc.hook_del(h)
        self._instr = len(seq)
        return (RunResult(reason, len(seq), self._read_oracle(), list(self._marks),
                          self.uc.reg_read(UC_ARM_REG_PC), err), seq)

    def build_ladder(self, writes, golden_length: int, rungs: int = 16):
        """Snapshot at regular INSTRUCTION-COUNT intervals.

        Spacing by count and not by address matters: the hash is a small amount
        of code executed an enormous number of times, so address-uniform rungs
        would all land inside one loop and buy nothing.
        """
        self.reset(writes)
        ladder = [self.snapshot()]
        stride = max(1, golden_length // rungs)
        for _ in range(rungs - 1):
            if not self._advance(stride):
                break
            ladder.append(self.snapshot())
        return ladder

    @staticmethod
    def nearest_rung(ladder, trigger: int):
        best = ladder[0]
        for s in ladder:
            if s.instr_count <= trigger:
                best = s
            else:
                break
        return best
