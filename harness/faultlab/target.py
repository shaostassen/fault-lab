"""Target loading and test-vector construction.

One binary serves every test vector. The linker pins .oracle and .noinit at
fixed addresses, the harness writes inputs there before reset, and no rebuild
is needed per vector. That is what makes a campaign across signed/forged/
rolled-back inputs cheap enough to run as a matrix.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

from elftools.elf.elffile import ELFFile

# --- memory map (must match common/link_cm3.ld) -----------------------------
FLASH_BASE, FLASH_SIZE = 0x00000000, 256 * 1024
RAM_BASE, RAM_SIZE = 0x20000000, 128 * 1024
ORACLE_BASE, ORACLE_WINDOW = 0x40010000, 0x1000
ORACLE_HALT = ORACLE_BASE + 0x00
ORACLE_MARK = ORACLE_BASE + 0x04

IMAGE_MAGIC = 0x4C464149
TAG_LEN, KEY_LEN = 32, 16
HEADER_LEN = 4 + TAG_LEN + 12          # magic + tag + version/length/entry
SIGNED_HDR = 12

ORACLE_STATE_FMT = "<8I"
ORACLE_STATE_SIZE = 32
ORACLE_MAGIC = 0x0FA17AB0

# Verdicts (mirror common/oracle.h). Sparse and high-Hamming-distance so no
# single bit flip in the verdict word turns REJECT into ACCEPT.
V_BOOT_ACCEPT = 0x0000A5C3
V_BOOT_REJECT = 0x00005A3C
V_SAFE_STATE = 0x0000C33C
V_RUN_COMPLETE = 0x00003CC3
V_ASSERT_FAIL = 0x0000FFF0

# sup_state_t (mirrors supervisor/safety.c). Direct-store field like the
# verdicts above, not an accumulator -- see classify.py's use of it instead
# of the marks-based MARK_SAFE_ENTERED bit.
SUP_INIT = 0x11
SUP_ARMED = 0x22
SUP_RUNNING = 0x44
SUP_SAFE = 0x88

MARK_NAMES = {
    0: "BOOT_ENTER", 1: "HDR_OK", 2: "VERSION_OK", 3: "SIG_OK", 4: "JUMP_TAKEN",
    5: "SUP_ARMED", 6: "SUP_RUNNING", 7: "FAULT_ASSERTED", 8: "SAFE_ENTERED",
}


@dataclass(slots=True)
class OracleState:
    magic: int = 0
    verdict: int = 0
    marks: int = 0
    cfi_counter: int = 0
    sup_state: int = 0
    pwm_duty: int = 0
    image_version: int = 0
    reserved: int = 0

    @classmethod
    def unpack(cls, raw: bytes) -> "OracleState":
        return cls(*struct.unpack(ORACLE_STATE_FMT, raw))

    @property
    def valid(self) -> bool:
        return self.magic == ORACLE_MAGIC


@dataclass(slots=True)
class Target:
    """A built firmware binary plus the symbol addresses the harness writes to."""
    name: str
    flash: bytes
    initial_sp: int
    entry: int
    symbols: dict[str, int] = field(default_factory=dict)

    @classmethod
    def load(cls, build_dir: str | Path) -> "Target":
        build_dir = Path(build_dir)
        flash = (build_dir / "fw.bin").read_bytes()
        sp, entry = struct.unpack("<II", flash[:8])
        syms: dict[str, int] = {}
        with open(build_dir / "fw.elf", "rb") as fh:
            elf = ELFFile(fh)
            symtab = elf.get_section_by_name(".symtab")
            for s in symtab.iter_symbols():
                if s.name:
                    syms[s.name] = s["st_value"]
        return cls(name=build_dir.name, flash=flash, initial_sp=sp,
                   entry=entry & ~1, symbols=syms)

    def sym(self, name: str) -> int:
        return self.symbols[name]


# --- test vectors -----------------------------------------------------------

@dataclass(slots=True)
class BootVector:
    """A secure-boot test input plus the ground truth about whether it SHOULD
    be accepted. The classifier needs `should_accept` -- the firmware never
    reports it, because a fault that corrupts the firmware's self-assessment
    must not be able to launder itself into a clean result."""
    name: str
    image: bytes
    key: bytes
    min_version: int
    should_accept: bool

    def writes(self, t: Target) -> list[tuple[int, bytes]]:
        return [
            (t.sym("g_image"), self.image),
            (t.sym("g_key"), self.key),
            (t.sym("g_min_version"), struct.pack("<I", self.min_version)),
        ]


def build_image(version: int = 2, body: bytes = b"HELLO-FIRMWARE-BODY",
                key: bytes = b"\x11" * KEY_LEN, entry: int = 0x1000,
                valid_tag: bool = True) -> bytes:
    signed = struct.pack("<III", version, len(body), entry)
    tag = hashlib.sha256(key + signed + body).digest()
    if not valid_tag:
        tag = bytes(b ^ 0xFF for b in tag)
    return struct.pack("<I", IMAGE_MAGIC) + tag + signed + body


def boot_vectors(key: bytes = b"\x11" * KEY_LEN) -> list[BootVector]:
    """The attacker-relevant inputs.

    FORGED and ROLLBACK are the ones that matter: any fault that flips either
    to accepted is a SEC_BYPASS. GENUINE is the control -- it establishes the
    golden trace and detects faults that break the happy path (denial of
    service, which is a finding but a much less interesting one).
    """
    return [
        BootVector("genuine", build_image(version=2, key=key), key, 1, True),
        BootVector("forged", build_image(version=2, key=key, valid_tag=False), key, 1, False),
        BootVector("rollback", build_image(version=0, key=key), key, 1, False),
        BootVector("bad_magic",
                   b"\x00\x00\x00\x00" + build_image(key=key)[4:], key, 1, False),
    ]


@dataclass(slots=True)
class SupervisorVector:
    name: str
    current_ma: int
    ticks_since_update: int
    setpoint: int
    iterations: int
    fault_asserted: bool

    def writes(self, t: Target) -> list[tuple[int, bytes]]:
        return [
            (t.sym("g_sensor_current_ma"), struct.pack("<I", self.current_ma)),
            (t.sym("g_ticks_since_update"), struct.pack("<I", self.ticks_since_update)),
            (t.sym("g_setpoint"), struct.pack("<I", self.setpoint)),
            (t.sym("g_iterations"), struct.pack("<I", self.iterations)),
        ]


def supervisor_vectors() -> list[SupervisorVector]:
    return [
        SupervisorVector("nominal", 1200, 5, 500, 40, False),
        SupervisorVector("overcurrent", 5000, 5, 500, 40, True),
        SupervisorVector("deadline_miss", 1200, 90, 500, 40, True),
    ]
