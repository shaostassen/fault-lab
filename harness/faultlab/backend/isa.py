"""Per-architecture descriptors: everything the backend has to vary by ISA.

WHY A DESCRIPTOR RATHER THAN BRANCHES IN THE BACKEND. The backend has exactly
four places that care about the architecture -- constructing the Uc, defining
registers on reset, deciding how many bytes a skip covers, and whether the PC
needs a mode bit set when execution starts. Scattering `if arch == ...` through
those four places is how a backend quietly grows two subtly different execution
paths, and this harness cannot afford that: the whole cross-architecture claim
rests on both targets being run by the *same* code with different constants.

THE MODE BIT IS THE TRAP WORTH NAMING. Cortex-M is Thumb-only, and Unicorn
requires the low bit of the PC set on every `emu_start` and after every skip to
say so. RISC-V has no such bit, and setting it produces a misaligned PC and an
immediate fault. It appears in three separate places in the backend, so it is a
field here rather than three remembered special cases.
"""

from __future__ import annotations

from dataclasses import dataclass

import capstone
from unicorn import (
    UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
    UC_ARCH_RISCV, UC_MODE_RISCV32,
)
from unicorn.arm_const import (
    UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_LR,
)
from unicorn.riscv_const import (
    UC_RISCV_REG_PC, UC_RISCV_REG_SP, UC_RISCV_REG_X0, UC_RISCV_REG_X1,
    UC_RISCV_REG_X31,
)


@dataclass(frozen=True, slots=True)
class Isa:
    name: str
    uc_arch: int
    uc_mode: int
    cs_arch: int
    cs_mode: int
    reg_pc: int
    reg_sp: int
    # Base register id for FaultModel.REG_XOR / REG_SET, whose `target` field is
    # an architectural register *number*: fault_reg_base + n.
    fault_reg_base: int
    # Registers reset() must define explicitly. See invariant 8 in CLAUDE.md --
    # "undefined" has to be one documented value, not whatever the previous run
    # happened to leave behind.
    reset_zero_regs: tuple[int, ...]
    # OR'd into the PC whenever execution starts or a skip moves it. 1 on
    # Cortex-M (Thumb), 0 on RISC-V, where it would misalign the PC instead.
    pc_mode_bit: int
    # Byte width of every instruction, or None when it must be decoded.
    fixed_insn_bytes: int | None


CM3 = Isa(
    name="cm3",
    uc_arch=UC_ARCH_ARM,
    uc_mode=UC_MODE_THUMB | UC_MODE_MCLASS,
    cs_arch=capstone.CS_ARCH_ARM,
    cs_mode=capstone.CS_MODE_THUMB,
    reg_pc=UC_ARM_REG_PC,
    reg_sp=UC_ARM_REG_SP,
    fault_reg_base=UC_ARM_REG_R0,
    reset_zero_regs=tuple(range(UC_ARM_REG_R0, UC_ARM_REG_R0 + 13)) + (UC_ARM_REG_LR,),
    pc_mode_bit=1,
    fixed_insn_bytes=None,  # Thumb-2 is 2 or 4 bytes; must decode
)

RV32 = Isa(
    name="rv32",
    uc_arch=UC_ARCH_RISCV,
    uc_mode=UC_MODE_RISCV32,
    cs_arch=capstone.CS_ARCH_RISCV,
    cs_mode=capstone.CS_MODE_RISCV32,
    reg_pc=UC_RISCV_REG_PC,
    reg_sp=UC_RISCV_REG_SP,
    fault_reg_base=UC_RISCV_REG_X0,
    # x1..x31. x0 is excluded because it is architecturally hardwired to zero:
    # writing it is a no-op on real silicon, so "defining" it would be
    # documenting a decision that does not exist.
    reset_zero_regs=tuple(range(UC_RISCV_REG_X1, UC_RISCV_REG_X31 + 1)),
    pc_mode_bit=0,
    # The firmware is built -march=rv32i with no compressed instructions
    # precisely so this is a constant (see firmware/Makefile). It keeps "skip k
    # instructions" an unambiguous fault model and lets the backend skip the
    # decode entirely on this target.
    fixed_insn_bytes=4,
)

BY_NAME = {isa.name: isa for isa in (CM3, RV32)}

# ELF e_machine -> ISA. Lets Target.load() identify a binary from the binary
# itself rather than making every caller pass an architecture it would have to
# get right, and keeps a build directory self-describing.
BY_ELF_MACHINE = {"EM_ARM": CM3, "EM_RISCV": RV32}
