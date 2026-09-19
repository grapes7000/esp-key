#!/usr/bin/env python3
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import serial

import esp_key

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
MAPPER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,126}$")


def validate_uuid(value):
    if not UUID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("expected a LUKS UUID")
    return value.lower()


def validate_mapper(value):
    if not MAPPER_RE.fullmatch(value):
        raise argparse.ArgumentTypeError("invalid mapper name")
    return value


def mapper_active(name):
    return subprocess.run(
        ["cryptsetup", "status", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def luks_device(uuid):
    path = Path("/dev/disk/by-uuid") / uuid
    if not path.exists():
        return None
    try:
        return str(path.resolve(strict=True))
    except FileNotFoundError:
        return None


def unlock_once(uuid, name):
    if mapper_active(name):
        return "already-active"

    device = luks_device(uuid)
    if device is None:
        return "volume-missing"

    try:
        ser = esp_key.connect(None)
    except (esp_key.EspKeyError, serial.SerialException):
        return "key-missing"

    with ser:
        key = esp_key.derive(ser, "luks:" + uuid)

    try:
        result = esp_key.run_with_keyfile(
            [
                "cryptsetup",
                "open",
                "--type",
                "luks",
                "--key-file",
                "{keyfile}",
                "--keyfile-size",
                str(esp_key.KEY_LEN),
                device,
                name,
            ],
            key,
        )
    finally:
        esp_key.zeroize(key)

    if result.returncode == 0 or mapper_active(name):
        return "unlocked"

    raise esp_key.EspKeyError(
        "an ESP-Key responded, but LUKS rejected its derived key for this volume"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Non-interactive ESP-Key auto-unlock helper"
    )
    parser.add_argument("--uuid", required=True, type=validate_uuid)
    parser.add_argument("--name", required=True, type=validate_mapper)
    parser.add_argument("--tries", type=int, default=12)
    parser.add_argument("--delay", type=float, default=0.5)
    args = parser.parse_args()

    if args.tries < 1 or args.tries > 120:
        parser.error("--tries must be between 1 and 120")
    if args.delay < 0 or args.delay > 10:
        parser.error("--delay must be between 0 and 10 seconds")
    if os.geteuid() != 0:
        print("esp-key: auto-unlock must run as root", file=sys.stderr)
        return 1

    last = None
    try:
        for attempt in range(args.tries):
            last = unlock_once(args.uuid, args.name)
            if last in ("unlocked", "already-active"):
                print(f"esp-key: {last}: /dev/mapper/{args.name}")
                return 0
            if attempt + 1 < args.tries:
                time.sleep(args.delay)
    except (esp_key.EspKeyError, serial.SerialException) as exc:
        print(f"esp-key: {exc}", file=sys.stderr)
        return 1

    # Missing counterpart is normal for a hotplug-triggered service: the other
    # udev event will start us again when it appears.
    print(f"esp-key: not ready ({last}); waiting for the other device")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
