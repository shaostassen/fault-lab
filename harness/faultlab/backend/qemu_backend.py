"""QEMU execution backend: a cross-validation oracle, not a campaign engine.

WHAT THIS IS FOR. Unicorn is a CPU emulator; QEMU with a board model is a
machine emulator. Running the same binary through both and comparing is a
correctness argument for the harness -- and a disagreement is a finding in its
own right, because it localises a place where the emulator abstraction changes
the security conclusion. That is the whole justification for a second backend,
and it is why this module deliberately does NOT try to be fast.

WHY IT CANNOT BE FAST, stated up front so nobody optimises the wrong thing.
Instruction-count triggering (faults.py) requires knowing exactly how many
instructions have executed. Unicorn gets that from `emu_start(count=N)` with
zero callbacks. Over GDB RSP the only primitive with that guarantee is `s`,
one round trip per guest instruction -- measured here at ~21,000 steps/s
against Unicorn's ~45,000 *runs* per second, where each run is thousands of
instructions. That is three to four orders of magnitude apart. Use this to
check tens or hundreds of interesting runs, never a campaign.

THE MACHINE, and why the memory map is the load-bearing detail. `mps2-an385`
is a Cortex-M3 board with SRAM at 0x00000000 and 0x20000000 -- which is the
map `common/link_cm3.ld` already targets, because that map was written to
Cortex-M convention in the first place. So the *identical binary* the Unicorn
campaigns run boots here with no relink. That matters more than convenience:
if the two backends ran different binaries, every disagreement would first
have to be argued not to be a link-address artifact, and the cross-validation
would prove much less.

TWO BEHAVIOURAL DIFFERENCES FROM THE UNICORN BACKEND, both deliberate:

  1. There is no MMIO hook. Unicorn intercepts writes to ORACLE_HALT and stops
     the CPU. QEMU has no such facility over RSP, and mps2-an385 has no device
     at 0x40010000 -- verified empirically that the store is absorbed without
     raising a BusFault, so the firmware proceeds into oracle_halt()'s trailing
     `for(;;)`. Halt is therefore detected by the PC ceasing to advance, and
     the verdict is read from `g_oracle` in RAM, which oracle_halt() writes
     *before* the MMIO store. The RAM copy is the real signal on both backends;
     the MMIO write is only ever a stop trigger.

  2. There is no snapshot ladder. Restoring RAM over RSP costs hundreds of
     round trips, which would dominate a backend already bounded by stepping.
     Every run replays from reset instead -- affordable precisely because this
     backend runs few, chosen experiments.
"""

from __future__ import annotations

import socket
import subprocess
import time

import capstone

from .gdb_rsp import GdbRsp, REG_PC, REG_SP
from .unicorn_backend import HaltReason, RunResult
from ..faults import FaultModel
from ..target import (
    Target, OracleState, RAM_BASE, RAM_SIZE, ORACLE_STATE_SIZE,
    ORACLE_MAGIC, ORACLE_STATE_FMT,
)

import struct

# How many consecutive identical PCs mean "this is oracle_halt()'s for(;;)"
# rather than a long instruction. Two would be enough for a self-branch; three
# costs one extra step and removes any doubt.
_SPIN_THRESHOLD = 3


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class QemuBackend:
    """Same observable contract as UnicornBackend for the operations that
    matter to cross-validation: reset(), trace(), run()."""

    MACHINE = {"cm3": ("mps2-an385", "cortex-m3")}

    def __init__(self, target: Target, port: int | None = None,
                 qemu: str = "qemu-system-arm") -> None:
        self.target = target
        isa_name = getattr(getattr(target, "isa", None), "name", "cm3")
        if isa_name not in self.MACHINE:
            # Deliberately a hard error rather than a silent fallback. RV32's
            # QEMU boards (virt, spike) put DRAM at 0x80000000, so the RV32
            # image would need relinking -- at which point the two backends are
            # no longer running the same bytes and the comparison is worth
            # much less. See the module docstring.
            raise NotImplementedError(
                f"no QEMU board with a matching memory map for ISA {isa_name!r}; "
                "only cm3 (mps2-an385) is supported")
        self.machine, self.cpu = self.MACHINE[isa_name]
        self.qemu_bin = qemu
        self.port = port or _free_port()
        self._proc: subprocess.Popen | None = None
        self.g = GdbRsp(port=self.port)
        self._md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._oracle_addr = target.sym("g_oracle")
        self._instr = 0

    # --- lifecycle ---------------------------------------------------------

    def start(self, elf_path: str) -> None:
        self._proc = subprocess.Popen(
            [self.qemu_bin, "-M", self.machine, "-cpu", self.cpu,
             "-kernel", elf_path, "-nographic", "-monitor", "none",
             "-serial", "none", "-S", "-gdb", f"tcp::{self.port}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # Wait for the stub to accept a connection rather than sleeping a fixed
        # interval: startup time varies with host load, and a too-short sleep
        # fails as a confusing connection-refused much later.
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"qemu exited: {self._proc.stdout.read()}")
            try:
                self.g.connect()
                return
            except (ConnectionRefusedError, OSError):
                time.sleep(0.05)
        raise TimeoutError("qemu gdbstub did not come up")

    def close(self) -> None:
        try:
            self.g.close()
        finally:
            if self._proc is not None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                self._proc = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # --- reset -------------------------------------------------------------

    def reset(self, writes) -> None:
        """Mirror UnicornBackend.reset(): zero RAM, seed the oracle, inject the
        test vector, then define SP/PC.

        RAM is zeroed explicitly even though Reset_Handler re-initialises .data
        and .bss itself. The point is not the firmware's correctness, it is that
        both backends must start from the *same* state for a comparison to mean
        anything -- and the Unicorn backend zeroes RAM. Anything left over here
        would be a difference between backends masquerading as a finding."""
        self.g.write_mem(RAM_BASE, b"\x00" * RAM_SIZE)
        self.g.write_mem(self._oracle_addr,
                         struct.pack(ORACLE_STATE_FMT, ORACLE_MAGIC, 0, 0, 0, 0, 0, 0, 0))
        for addr, data in writes:
            self.g.write_mem(addr, data)
        # Cortex-M is Thumb-only: the low PC bit is the mode bit, and QEMU
        # faults immediately without it. Same reasoning as backend/isa.py.
        self.g.write_reg(REG_SP, self.target.initial_sp)
        self.g.write_reg(REG_PC, self.target.entry | 1)
        self._instr = 0

    def _read_oracle(self) -> OracleState:
        return OracleState.unpack(self.g.read_mem(self._oracle_addr, ORACLE_STATE_SIZE))

    # --- faults ------------------------------------------------------------

    def _skip_bytes(self, pc: int, k: int) -> int:
        """Byte width of the next k instructions -- identical logic to the
        Unicorn backend, because a skip that covered a different number of
        bytes would make the two backends run different experiments."""
        code = self.g.read_mem(pc & ~1, 4 * k + 8)
        total = 0
        for i, insn in enumerate(self._md.disasm(code, pc & ~1)):
            if i >= k:
                break
            total += insn.size
        return total or 2

    def _apply(self, f) -> None:
        if f.model == FaultModel.SKIP:
            pc = self.g.pc & ~1
            self.g.pc = (pc + self._skip_bytes(pc, f.value)) | 1
        elif f.model == FaultModel.REG_XOR:
            cur = self.g.read_reg(f.target)
            self.g.write_reg(f.target, (cur ^ f.value) & 0xFFFFFFFF)
        elif f.model == FaultModel.REG_SET:
            self.g.write_reg(f.target, f.value & 0xFFFFFFFF)
        elif f.model == FaultModel.MEM_XOR:
            cur = int.from_bytes(self.g.read_mem(f.target, f.width), "little")
            self.g.write_mem(f.target, (cur ^ f.value).to_bytes(f.width, "little"))
        else:
            raise NotImplementedError(f"fault model {f.model!r} not supported on QEMU")

    # --- execution ---------------------------------------------------------

    def _run_until_halt(self, budget: int, record: list | None = None):
        """Step until the PC stops advancing (oracle_halt's for(;;)) or the
        budget runs out. Returns (halt_reason, instructions_executed)."""
        prev_pc, stuck = None, 0
        while self._instr < budget:
            pc = self.g.pc & ~1
            if record is not None:
                record.append(pc)
            if pc == prev_pc:
                stuck += 1
                if stuck >= _SPIN_THRESHOLD:
                    # Back out every spin iteration, so the count means the same
                    # thing on both backends: instructions up to and including
                    # the MMIO store that signals halt, excluding oracle_halt's
                    # trailing for(;;). Unicorn never executes that loop at all
                    # -- its MMIO hook calls emu_stop() during the store -- so
                    # counting even one iteration here would report a different
                    # number for identical execution, and instruction counts are
                    # what fault triggers are expressed in.
                    self._instr -= _SPIN_THRESHOLD
                    if record is not None:
                        # One more than _instr backs out: the iteration that
                        # detects the spin has already appended its PC without
                        # stepping, so the record runs one ahead of the count.
                        del record[-(_SPIN_THRESHOLD + 1):]
                    return HaltReason.ORACLE, self._instr
            else:
                stuck = 0
            prev_pc = pc
            self.g.step()
            self._instr += 1
        return HaltReason.BUDGET, self._instr

    def trace(self, budget: int):
        """Golden run, recording the PC sequence -- the QEMU analogue of
        UnicornBackend.trace()."""
        seq: list[int] = []
        reason, n = self._run_until_halt(budget, record=seq)
        o = self._read_oracle()
        return RunResult(reason, n, o, [], self.g.pc & ~1), seq

    def run(self, budget: int, faults=None, writes=None) -> RunResult:
        """One faulted run, from reset.

        `writes` is required rather than optional because there is no snapshot
        ladder to resume from: every run replays from the beginning, so it needs
        the vector to re-inject."""
        if writes is not None:
            self.reset(writes)
        if faults is not None:
            for f in faults.faults:
                target_n = f.trigger - self._instr
                if target_n < 0:
                    raise ValueError("faults must be in ascending trigger order")
                for _ in range(target_n):
                    if self._instr >= budget:
                        break
                    self.g.step()
                    self._instr += 1
                # A skipped instruction did not execute, so _instr does not
                # advance here -- the same cumulative-trigger semantics as the
                # Unicorn backend (invariant 9 in CLAUDE.md). Keeping these
                # identical is what makes a multi-fault comparison meaningful.
                self._apply(f)
        reason, n = self._run_until_halt(budget)
        return RunResult(reason, n, self._read_oracle(), [], self.g.pc & ~1)
