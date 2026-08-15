"""Minimal GDB Remote Serial Protocol client.

WHY THIS EXISTS RATHER THAN A LIBRARY. The QEMU backend needs exactly five
operations -- read/write memory, read/write registers, and single-step -- over
a protocol that is small, stable, and fully specified. Pulling in a debugger
framework to get those five would add a dependency heavier than the code it
replaces, and would put a layer between this harness and the one thing that
has to stay exact: how many instructions have executed. Fault injection here
triggers on instruction count (see faults.py), so the step primitive is not an
implementation detail, it *is* the contract.

PROTOCOL, in the two paragraphs that matter:

A packet is `$<payload>#<checksum>`, where checksum is the sum of the payload
bytes mod 256, two lowercase hex digits. The receiver replies `+` to accept or
`-` to request retransmission. Responses arrive in the same frame format and
must themselves be acked. Everything else is payload conventions: `m`/`M` for
memory, `p`/`P` for one register, `s` for step, `c` for continue, `?` for halt
reason.

Notification packets (`%Stop:...`) and the `O` console-output packet can arrive
unsolicited, interleaved with the reply you are waiting for. `_recv()` skips
them rather than mistaking one for a command response -- an easy source of
desynchronisation that shows up as a hang three commands later, far from where
it was caused.
"""

from __future__ import annotations

import socket


class RspError(RuntimeError):
    pass


# ARM gdbstub register numbering (QEMU's arm target.xml). r0-r12 are 0-12,
# then sp/lr/pc, then the status register -- which sits at 25, NOT 16, because
# 16-24 are the legacy FPA slots GDB still reserves for ARM targets.
REG_SP = 13
REG_LR = 14
REG_PC = 15
REG_XPSR = 25


class GdbRsp:
    def __init__(self, host: str = "127.0.0.1", port: int = 1234,
                 timeout: float = 10.0) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self._sock: socket.socket | None = None
        self._buf = bytearray()

    # --- framing -----------------------------------------------------------

    @staticmethod
    def _checksum(payload: bytes) -> bytes:
        return f"{sum(payload) & 0xFF:02x}".encode()

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), self.timeout)
        self._sock.settimeout(self.timeout)
        # TCP_NODELAY is not optional here, it is the difference between this
        # backend being usable and not. RSP is a strict request/response of
        # tiny packets, which is the exact pathological case for Nagle's
        # algorithm interacting with delayed ACK: measured 24 steps/s without
        # it, ~100x that with it. Single-stepping is already the slow path
        # (one round trip per guest instruction); paying a 40 ms timer on top
        # of each one puts a single 8,000-instruction trace at five minutes.
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # Announce no special capabilities. QEMU is permissive about this, but
        # sending it flushes any greeting and proves the link is alive before
        # a real command depends on it.
        self.cmd("qSupported")

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _read_byte(self) -> int:
        while not self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise RspError("connection closed by stub")
            self._buf.extend(chunk)
        return self._buf.pop(0)

    def _send(self, payload: str) -> None:
        raw = payload.encode()
        pkt = b"$" + raw + b"#" + self._checksum(raw)
        self._sock.sendall(pkt)
        # The stub acks with '+'. A '-' means it wants the packet again.
        for _ in range(3):
            ack = self._read_byte()
            if ack == ord("+"):
                return
            if ack == ord("-"):
                self._sock.sendall(pkt)
                continue
            # Anything else is an out-of-band frame that arrived before our
            # ack; push it back and keep waiting.
            self._buf.insert(0, ack)
            return
        raise RspError(f"stub kept nacking packet: {payload!r}")

    def _recv(self) -> str:
        while True:
            b = self._read_byte()
            if b != ord("$"):
                continue  # skip acks and stray bytes between frames
            body = bytearray()
            while True:
                c = self._read_byte()
                if c == ord("#"):
                    break
                body.append(c)
            got = bytes((self._read_byte(), self._read_byte()))
            if got.lower() != self._checksum(bytes(body)):
                self._sock.sendall(b"-")
                continue
            self._sock.sendall(b"+")
            text = bytes(body).decode(errors="replace")
            # Console output is not a reply to the command we just sent.
            # Dropping it keeps request and response aligned; treating one as a
            # reply desynchronises the stream in a way that surfaces much later
            # and looks like a hang.
            #
            # The test has to be exact, not `startswith("O")`: "OK" is the
            # single most common real reply in this protocol and it also starts
            # with O. A console packet is 'O' followed by hex-encoded bytes, so
            # require that shape -- an earlier, looser version of this check
            # silently ate every OK and turned every memory write into a
            # timeout.
            if (len(text) > 1 and text[0] == "O" and text != "OK"
                    and all(c in "0123456789abcdefABCDEF" for c in text[1:])):
                continue
            return text

    def cmd(self, payload: str) -> str:
        self._send(payload)
        return self._recv()

    # --- memory ------------------------------------------------------------

    def read_mem(self, addr: int, length: int) -> bytes:
        out = bytearray()
        # The stub caps packet size; chunk so callers can read a whole RAM
        # image without thinking about it.
        remaining, cursor = length, addr
        while remaining > 0:
            n = min(remaining, 512)
            r = self.cmd(f"m{cursor:x},{n:x}")
            if r.startswith("E") or not r:
                raise RspError(f"read_mem({cursor:#x}, {n}) failed: {r!r}")
            out.extend(bytes.fromhex(r))
            cursor += n
            remaining -= n
        return bytes(out)

    def write_mem(self, addr: int, data: bytes) -> None:
        cursor = 0
        while cursor < len(data):
            chunk = data[cursor:cursor + 512]
            r = self.cmd(f"M{addr + cursor:x},{len(chunk):x}:{chunk.hex()}")
            if r != "OK":
                raise RspError(f"write_mem({addr + cursor:#x}) failed: {r!r}")
            cursor += len(chunk)

    # --- registers ---------------------------------------------------------

    def read_reg(self, n: int) -> int:
        r = self.cmd(f"p{n:x}")
        if r.startswith("E") or not r:
            raise RspError(f"read_reg({n}) failed: {r!r}")
        return int.from_bytes(bytes.fromhex(r), "little")

    def write_reg(self, n: int, value: int) -> None:
        payload = (value & 0xFFFFFFFF).to_bytes(4, "little").hex()
        r = self.cmd(f"P{n:x}={payload}")
        if r != "OK":
            raise RspError(f"write_reg({n}, {value:#x}) failed: {r!r}")

    @property
    def pc(self) -> int:
        return self.read_reg(REG_PC)

    @pc.setter
    def pc(self, value: int) -> None:
        self.write_reg(REG_PC, value)

    # --- execution ---------------------------------------------------------

    def step(self) -> str:
        """Execute exactly one instruction. Returns the stop reply.

        This is the whole reason the QEMU backend is a cross-validation oracle
        rather than a campaign engine: one round trip per instruction, versus
        Unicorn's emu_start(count=N) which advances N instructions with zero
        callbacks. Correct, and about three orders of magnitude slower."""
        return self.cmd("s")

    def cont(self) -> str:
        return self.cmd("c")

    def halt_reason(self) -> str:
        return self.cmd("?")
