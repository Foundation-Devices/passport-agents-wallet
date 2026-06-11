# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Prime HWI driver skeleton.

A `hwilib.hwwclient.HardwareWalletClient` for Passport Prime, so libnunchuk /
nunchuk-cli (and Sparrow, Specter, Bitcoin Core) can reach Prime over HWI like any
hardware wallet. See docs/HWI.md. USB-CDC transport is proven (nostr usb_cdc.rs); this
driver is functional over the file bridge today (get_pubkey_at_path / sign verified).

Status: file-bridge transport FUNCTIONAL (enumerate + get_pubkey_at_path verified). The bitcoin/PSBT logic lives on Prime; this is the host-side glue
that frames requests over a transport and returns Prime's replies. Two transports:

  - PrimeFileTransport  : the file bridge (works today; same as `prime-signer`)
  - PrimeSerialTransport : USB-CDC, Prime's newline-JSON protocol (device phase;
                           reuse nostr-signer src/transport/usb_cdc.rs)

Drop into hwilib/devices/prime.py and register in hwilib's device list to make
`hwi enumerate` / `hwi -t prime ...` and libnunchuk's HWI path see Prime.
"""

from __future__ import annotations

import json
import os
import time

# In-tree these come from hwilib; imported lazily so the skeleton is readable alone.
try:
    from hwilib.hwwclient import HardwareWalletClient
    from hwilib.errors import DeviceConnectionError, UnavailableActionError
    from hwilib.key import ExtendedKey
    from hwilib.psbt import PSBT
    from hwilib.common import AddressType
except Exception:  # skeleton-readable without hwilib installed
    HardwareWalletClient = object
    DeviceConnectionError = RuntimeError
    UnavailableActionError = NotImplementedError
    ExtendedKey = PSBT = AddressType = object


# --- Transports -------------------------------------------------------------

class PrimeFileTransport:
    """File bridge (today). Mirrors `host/prime-signer`: drop a request, await reply.
    Prime runs in HSM mode and auto-signs in-policy; over-policy is held for approval.
    """

    def __init__(self, bridge: str | None = None, wait_secs: int = 30):
        self.bridge = bridge or os.path.expanduser(
            os.environ.get("PRIME_BRIDGE", "~/.passport-nunchuk-signer-keyos")
        )
        self.wait_secs = wait_secs

    def _path(self, name: str) -> str:
        return os.path.join(self.bridge, name)

    def read_key(self) -> str:
        with open(self._path("passport-key.txt")) as f:  # [fp/48'/1'/0'/2']xpub
            return f.read().strip()

    def sign_psbt_b64(self, psbt_b64: str) -> str:
        out = self._path("signed-psbt.b64.txt")
        if os.path.exists(out):
            os.remove(out)
        with open(self._path("unsigned.psbt"), "w") as f:
            f.write(psbt_b64)
        for _ in range(self.wait_secs):
            if os.path.exists(out) and not os.path.exists(self._path("unsigned.psbt")):
                with open(out) as f:
                    return f.read().strip()
            time.sleep(1)
        if os.path.exists(self._path("unsigned.psbt")):
            raise UnavailableActionError(
                "over policy: Prime is holding this spend for on-device approval"
            )
        raise DeviceConnectionError("timed out waiting for Prime signature")

    def xpub_at_path(self, path: str) -> str:
        """[fp/path]xpub at an arbitrary BIP32 path (HWI get_pubkey_at_path).
        Writes xpub-request.txt, Prime's poller answers xpub-response.txt."""
        out = self._path("xpub-response.txt")
        if os.path.exists(out):
            os.remove(out)
        with open(self._path("xpub-request.txt"), "w") as f:
            f.write(path)
        for _ in range(10):
            if os.path.exists(out):
                with open(out) as f:
                    return f.read().strip()
            time.sleep(1)
        raise DeviceConnectionError(f"no xpub response for {path}")


class PrimeSerialTransport:
    """USB-CDC, Prime's newline-JSON line protocol (device phase). Prime exposes a
    second CDC-ACM interface (src/usb_cdc.rs); each `\\n`-terminated line is one
    `device_protocol::Request`, the reply one `device_protocol::Response`:
      {"cmd":"fingerprint"}            -> {"result":"fingerprint","fingerprint":".."}
      {"cmd":"xpub","path":"m/.."}     -> {"result":"key","key":"[fp/..]xpub"}
      {"cmd":"sign","psbt":"<b64>"}    -> {"result":"signed","psbt":".."} | {"result":"pending",..}
      {"cmd":"showaddr","index":N}     -> {"result":"address","address":".."}
    Same protocol the file bridge dispatches, so device and sim behave identically.
    """

    VID, PID = 0x1307, 0x0165  # Passport normal mode (SAM-BA is 0x03eb:0x6124)
    DEFAULT_KEY_PATH = "m/48'/1'/0'/2'"  # P2WSH multisig account (matches the bridge key)

    # Retry/backoff: a freshly-plugged Prime, a reconnecting CDC interface, or a port
    # briefly held by udev/another reader is transient - retry with capped exponential
    # backoff before giving up. Tunable via env for headless/CI. The device end already
    # parks on HostDisconnected (usb_cdc.rs), so this is the host half of the same story.
    CONNECT_RETRIES = int(os.environ.get("PRIME_CONNECT_RETRIES", "5"))
    BACKOFF_BASE = float(os.environ.get("PRIME_BACKOFF_BASE", "0.5"))  # seconds
    BACKOFF_CAP = float(os.environ.get("PRIME_BACKOFF_CAP", "4.0"))    # seconds

    def __init__(self, path: str, baud: int = 115200, timeout: int = 30):
        self.path = path
        self.baud = baud
        self.timeout = timeout
        self.ser = self._open()

    def _backoff(self, attempt: int) -> float:
        """Capped exponential backoff for retry `attempt` (0-indexed)."""
        return min(self.BACKOFF_CAP, self.BACKOFF_BASE * (2 ** attempt))

    def _open(self):
        """Open the port, retrying transient failures with backoff. Opening is where
        "Prime not plugged in" surfaces (port absent, or busy). After the retries are
        exhausted we raise HWI's DeviceConnectionError so libnunchuk / Sparrow / Core
        report a clean "device not connected" instead of a raw pyserial trace."""
        import serial  # pyserial; lazy so the skeleton stays importable without it
        last = None
        for attempt in range(self.CONNECT_RETRIES):
            try:
                return serial.Serial(self.path, self.baud, timeout=2)
            except serial.SerialException as e:
                last = e
                if attempt + 1 < self.CONNECT_RETRIES:
                    time.sleep(self._backoff(attempt))
        raise DeviceConnectionError(
            f"Prime not reachable on {self.path} after {self.CONNECT_RETRIES} tries: {last}"
        )

    def _reconnect(self) -> None:
        """Re-open after a mid-session drop (cable yanked + replugged)."""
        try:
            self.ser.close()
        except Exception:
            pass
        self.ser = self._open()

    def _rpc(self, request: dict) -> dict:
        import serial
        line = (json.dumps(request, separators=(",", ":")) + "\n").encode()
        deadline = time.time() + self.timeout
        reconnects = 0
        # Send, then read until a full line arrives or the deadline passes. A port
        # error mid-call (unplug) triggers one reconnect+resend per drop, bounded by
        # CONNECT_RETRIES so a permanently-gone device still fails in finite time.
        while time.time() < deadline:
            try:
                self.ser.reset_input_buffer()
                self.ser.write(line)
                self.ser.flush()
                while time.time() < deadline:
                    raw = self.ser.readline()  # blocks up to per-read timeout (2s)
                    if not raw:
                        continue
                    text = raw.strip()
                    if not text:
                        continue
                    return json.loads(text)
            except (serial.SerialException, OSError) as e:
                if reconnects >= self.CONNECT_RETRIES:
                    raise DeviceConnectionError(f"Prime connection lost: {e}")
                reconnects += 1
                time.sleep(self._backoff(reconnects - 1))
                self._reconnect()
                continue
        raise DeviceConnectionError("timed out waiting for Prime response")

    def read_key(self) -> str:
        return self.xpub_at_path(self.DEFAULT_KEY_PATH)

    def xpub_at_path(self, path: str) -> str:
        resp = self._rpc({"cmd": "xpub", "path": path})
        if resp.get("result") == "key":
            return resp["key"]
        raise DeviceConnectionError(resp.get("message", f"no xpub for {path}"))

    def sign_psbt_b64(self, psbt_b64: str) -> str:
        resp = self._rpc({"cmd": "sign", "psbt": psbt_b64})
        result = resp.get("result")
        if result == "signed":
            return resp["psbt"]
        if result == "pending":
            raise UnavailableActionError(
                "over policy: Prime is holding this spend for on-device approval"
            )
        raise DeviceConnectionError(resp.get("message", "sign failed"))

    def close(self) -> None:
        try:
            self.ser.close()
        except Exception:
            pass


# --- Driver -----------------------------------------------------------------

class PrimeClient(HardwareWalletClient):
    """HWI client for Passport Prime."""

    def __init__(self, path: str = "", password: str = "", expert: bool = False, chain=None):
        super().__init__(path, password, expert, chain)
        # path="" -> file bridge; a real device path -> serial transport.
        self.transport = PrimeFileTransport() if not path else PrimeSerialTransport(path)

    # -- keys --
    def get_master_fingerprint(self) -> bytes:
        key = self.transport.read_key()           # "[d38570d3/48'/1'/0'/2']tpub..."
        fp_hex = key[1:].split("/", 1)[0]
        return bytes.fromhex(fp_hex)

    def get_pubkey_at_path(self, bip32_path: str) -> "ExtendedKey":
        # Functional: Prime derives [fp/path]xpub on request (see xpub-request bridge).
        key = self.transport.xpub_at_path(bip32_path)   # "[fp/path]tpub..."
        xpub = key.split("]", 1)[1]
        return ExtendedKey.deserialize(xpub)

    # -- signing --
    def sign_tx(self, psbt: "PSBT") -> "PSBT":
        # Prime applies its HSM policy: in-policy -> signed unattended; over-policy ->
        # held for an on-device approval (UnavailableActionError; caller retries).
        signed_b64 = self.transport.sign_psbt_b64(psbt.serialize())
        out = PSBT()
        out.deserialize(signed_b64)
        return out

    def display_multisig_address(self, addr_type: "AddressType", multisig) -> str:
        # Prime can verify/derive an address from a registered descriptor on-screen.
        raise UnavailableActionError("display_multisig_address: TODO on-device showaddr")

    # -- capabilities --
    def can_sign_taproot(self) -> bool:
        return False  # P2WSH only in v1

    # -- lifecycle owned by the device, not HWI --
    def setup_device(self, label="", passphrase=""):
        raise UnavailableActionError("Prime manages its own seed/PIN on-device")

    def wipe_device(self):
        raise UnavailableActionError("Prime manages its own seed/PIN on-device")

    def close(self) -> None:
        closer = getattr(self.transport, "close", None)
        if callable(closer):
            closer()


def _scan_usb_ports() -> list[str]:
    """Serial ports whose USB VID/PID match Prime in normal mode. Empty if pyserial
    is absent or nothing is plugged in - the "Prime not connected" signal."""
    try:
        from serial.tools import list_ports
    except Exception:
        return []
    return [
        p.device
        for p in list_ports.comports()
        if p.vid == PrimeSerialTransport.VID and p.pid == PrimeSerialTransport.PID
    ]


def enumerate(password: str = "", expert: bool = False, chain=None):
    """HWI device discovery. Reports a Prime over USB (matched by VID/PID) when one
    is plugged in; otherwise falls back to the file bridge for the hosted sim. An
    empty list means no Prime found (HWI's standard "not connected" result)."""
    found = []
    # Real hardware: one entry per matching USB serial port -> serial transport.
    for port in _scan_usb_ports():
        found.append({
            "type": "prime",
            "model": "passport_prime",
            "path": port,           # non-empty -> serial transport
            "needs_pin_sent": False,
            "needs_passphrase_sent": False,
        })
    # Hosted sim: the app-data bridge dir stands in for a connected device.
    bridge = os.path.expanduser(
        os.environ.get("PRIME_BRIDGE", "~/.passport-nunchuk-signer-keyos")
    )
    if not found and os.path.isdir(bridge):
        found.append({
            "type": "prime",
            "model": "passport_prime",
            "path": "",             # "" -> file-bridge transport
            "needs_pin_sent": False,
            "needs_passphrase_sent": False,
        })
    return found
