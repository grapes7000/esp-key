#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager

import serial
from serial.tools import list_ports

PROTOCOL = "ESP-KEY/0.1"
DOMAIN = b"esp-key/luks/v0.1\x00"
KEY_LEN = 32
BAUD = 115200
SERIAL_TIMEOUT = 0.25
COMMAND_TIMEOUT = 3.0


class EspKeyError(RuntimeError):
    pass


def zeroize(buf):
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def candidate_ports(explicit=None):
    if explicit:
        return [explicit]

    ports = list(list_ports.comports())
    candidates = []
    for p in ports:
        hwid = (p.hwid or "").upper()
        desc = (p.description or "").upper()
        if p.vid == 0x303A or "303A" in hwid or "ESP" in desc or "XIAO" in desc:
            candidates.append(p.device)

    if not candidates:
        available = ", ".join(p.device for p in ports) or "none"
        raise EspKeyError(
            f"No likely ESP serial port found (available: {available}). "
            "Use --port /dev/ttyACM0 if needed."
        )
    return candidates


def read_response(ser, expected_prefix, timeout=COMMAND_TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = ser.readline()
        if not raw:
            continue
        line = raw.decode("ascii", errors="replace").strip()
        if not line or line.startswith("READY "):
            continue
        if line.startswith("ERR "):
            raise EspKeyError(f"device returned: {line}")
        if line.startswith(expected_prefix):
            return line
        # Ignore ROM/bootloader noise and unrelated serial chatter while waiting
        # for the protocol response we asked for.
    raise EspKeyError(f"ESP-Key timed out waiting for {expected_prefix!r}")


def command(ser, line, expected_prefix, timeout=COMMAND_TIMEOUT):
    if "\n" in line or "\r" in line or len(line) > 160:
        raise EspKeyError("invalid protocol command")
    try:
        ser.write((line + "\n").encode("ascii"))
        ser.flush()
    except (serial.SerialException, serial.SerialTimeoutException) as exc:
        raise EspKeyError(f"serial write failed: {exc}") from exc
    return read_response(ser, expected_prefix, timeout)


def probe_port(port, timeout=2.5):
    try:
        ser = serial.Serial(
            port,
            BAUD,
            timeout=SERIAL_TIMEOUT,
            write_timeout=1.0,
        )
    except serial.SerialException:
        return None

    try:
        time.sleep(0.25)
        try:
            ser.reset_input_buffer()
        except serial.SerialException:
            pass

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                response = command(ser, "PING", "OK ESP-KEY/", timeout=0.6)
            except EspKeyError:
                time.sleep(0.10)
                continue

            if response == f"OK {PROTOCOL}":
                status = command(ser, "STATUS", "STATUS ", timeout=0.6)
                if status != "STATUS storage=ok":
                    raise EspKeyError(f"device storage is not healthy: {status}")
                return ser

        ser.close()
        return None
    except Exception:
        ser.close()
        raise


def connect(port=None):
    ports = candidate_ports(port)
    found = []
    for candidate in ports:
        ser = probe_port(candidate, timeout=5.0 if port else 2.5)
        if ser is not None:
            found.append(ser)

    if not found:
        if port:
            raise EspKeyError(f"No ESP-Key responding on {port}")
        raise EspKeyError("No ESP-Key responded on the detected ESP serial ports")

    if len(found) > 1:
        names = ", ".join(s.port for s in found)
        for s in found:
            s.close()
        raise EspKeyError(f"Multiple ESP-Key devices found ({names}); select one with --port")

    return found[0]


def derive(ser, context):
    if not context or len(context.encode("utf-8")) > 1024:
        raise EspKeyError("context must be 1..1024 UTF-8 bytes")

    challenge = hashlib.sha256(DOMAIN + context.encode("utf-8")).digest()
    response = command(ser, "HMAC " + challenge.hex(), "HMAC ")
    mac_hex = response[5:].strip()
    if len(mac_hex) != KEY_LEN * 2:
        raise EspKeyError("device returned an invalid HMAC length")

    try:
        raw = bytearray.fromhex(mac_hex)
    except ValueError as exc:
        raise EspKeyError("device returned a non-hex HMAC") from exc

    if len(raw) != KEY_LEN:
        zeroize(raw)
        raise EspKeyError("device returned an invalid HMAC")

    try:
        # Keep the v0.1 KDF stable: HMAC(device_response, domain || "key").
        return bytearray(hmac.new(raw, DOMAIN + b"key", hashlib.sha256).digest())
    finally:
        zeroize(raw)


def require_cryptsetup():
    if shutil.which("cryptsetup") is None:
        raise EspKeyError("cryptsetup was not found in PATH")


def luks_uuid(device):
    require_cryptsetup()
    result = subprocess.run(
        ["cryptsetup", "luksUUID", device],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        raise EspKeyError(message or f"{device} is not a readable LUKS volume")
    uuid = result.stdout.strip().lower()
    if not uuid:
        raise EspKeyError("cryptsetup returned an empty LUKS UUID")
    return uuid


@contextmanager
def key_memfd(key):
    if not hasattr(os, "memfd_create"):
        raise EspKeyError("this Linux/Python build does not support memfd_create")

    flags = getattr(os, "MFD_CLOEXEC", 0)
    fd = os.memfd_create("esp-key-luks-key", flags=flags)
    try:
        view = memoryview(key)
        written = 0
        while written < len(view):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise EspKeyError("failed to stage derived key in memory")
            written += n
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd, f"/proc/self/fd/{fd}"
    finally:
        try:
            os.ftruncate(fd, 0)
        except OSError:
            pass
        os.close(fd)


def run_with_keyfile(args, key):
    with key_memfd(key) as (fd, path):
        command_line = [path if arg == "{keyfile}" else arg for arg in args]
        return subprocess.run(command_line, pass_fds=(fd,), check=False)


def cmd_status(args):
    with connect(args.port) as ser:
        identity = command(ser, "ID", "ID ")
        print(f"PORT {ser.port}")
        print(identity)
        print(f"OK {PROTOCOL}")


def cmd_fingerprint(args):
    with connect(args.port) as ser:
        key = derive(ser, args.context)
    try:
        print(hashlib.sha256(key).hexdigest())
    finally:
        zeroize(key)


def cmd_key(args):
    if not args.unsafe:
        raise EspKeyError("refusing to print raw key material without --unsafe")
    print("WARNING: writing raw derived key bytes to stdout", file=sys.stderr)
    with connect(args.port) as ser:
        key = derive(ser, args.context)
    try:
        sys.stdout.buffer.write(key)
        sys.stdout.buffer.flush()
    finally:
        zeroize(key)


def cmd_unlock(args):
    uuid = luks_uuid(args.device)
    context = "luks:" + uuid
    with connect(args.port) as ser:
        key = derive(ser, context)

    try:
        result = run_with_keyfile(
            [
                "cryptsetup",
                "open",
                "--type",
                "luks",
                "--key-file",
                "{keyfile}",
                "--keyfile-size",
                str(KEY_LEN),
                args.device,
                args.name,
            ],
            key,
        )
    finally:
        zeroize(key)

    if result.returncode != 0:
        raise EspKeyError(f"cryptsetup open failed with exit code {result.returncode}")
    print(f"Unlocked {args.device} as /dev/mapper/{args.name}")


def cmd_enroll(args):
    uuid = luks_uuid(args.device)
    context = "luks:" + uuid
    print(
        "This adds ESP-Key as a NEW LUKS keyslot; "
        "your existing recovery passphrase stays intact."
    )

    with connect(args.port) as ser:
        key = derive(ser, context)

    try:
        # The derived new key is passed via an inherited anonymous memfd.
        # stdin/TTY remains untouched so cryptsetup can ask for the existing
        # recovery passphrase interactively.
        result = run_with_keyfile(
            [
                "cryptsetup",
                "luksAddKey",
                "--new-keyfile",
                "{keyfile}",
                "--new-keyfile-size",
                str(KEY_LEN),
                args.device,
            ],
            key,
        )
        if result.returncode != 0:
            raise EspKeyError(f"cryptsetup luksAddKey failed with exit code {result.returncode}")

        verify = run_with_keyfile(
            [
                "cryptsetup",
                "open",
                "--type",
                "luks",
                "--test-passphrase",
                "--key-file",
                "{keyfile}",
                "--keyfile-size",
                str(KEY_LEN),
                args.device,
            ],
            key,
        )
        if verify.returncode != 0:
            raise EspKeyError(
                "the keyslot was added, but ESP-Key verification failed; "
                "keep using your recovery passphrase"
            )
    finally:
        zeroize(key)

    print("ESP-Key keyslot enrolled and verified.")


def build_parser():
    parser = argparse.ArgumentParser(prog="esp-key")
    parser.add_argument("--port", help="serial device, e.g. /dev/ttyACM0")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("status", help="probe the connected ESP-Key")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("fingerprint", help="print a hash of a derived test key")
    p.add_argument("context")
    p.set_defaults(fn=cmd_fingerprint)

    p = sub.add_parser("key", help="emit raw derived key bytes (dangerous)")
    p.add_argument("context")
    p.add_argument("--unsafe", action="store_true")
    p.set_defaults(fn=cmd_key)

    p = sub.add_parser("enroll", help="add ESP-Key to a LUKS keyslot")
    p.add_argument("device")
    p.set_defaults(fn=cmd_enroll)

    p = sub.add_parser("unlock", help="unlock a LUKS volume with ESP-Key")
    p.add_argument("device")
    p.add_argument("--name", default="esp-key-vault")
    p.set_defaults(fn=cmd_unlock)

    return parser


def main():
    args = build_parser().parse_args()
    try:
        args.fn(args)
    except (EspKeyError, serial.SerialException) as exc:
        print(f"esp-key: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nesp-key: cancelled", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
