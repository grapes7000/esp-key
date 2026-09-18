# esp-key

Experimental XIAO ESP32-C3 possession key for unlocking **LUKS2** volumes.

> **v0.1 is a prototype. Use only disposable/test data.** The device secret is stored in ESP32 NVS and is not yet protected with Secure Boot, flash encryption, eFuse HMAC, PIN entry, or a trusted display.

## Design

The C3 generates a random 256-bit secret on first boot. The host derives a deterministic, volume-bound challenge from the LUKS UUID, asks the C3 for HMAC-SHA256, then derives a separate 256-bit LUKS key. The device secret is never sent over serial.

A normal recovery passphrase remains in another LUKS keyslot.

## Firmware

Requires PlatformIO:

```bash
cd firmware
pio run -t upload
pio device monitor
```

Expected boot message: `READY ESP-KEY/0.1`.

## Host

Requires Python 3, pyserial, and cryptsetup:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r host/requirements.txt
python host/esp_key.py status
```

If autodetection misses the board, add `--port /dev/ttyACM0` before the subcommand.

## Safe v0.1 test

Create a disposable 64 MiB file and initialize it with a recovery passphrase:

```bash
truncate -s 64M /tmp/esp-key-test.img
sudo cryptsetup luksFormat --type luks2 /tmp/esp-key-test.img
```

Enroll the C3 into a second keyslot (cryptsetup will ask for the existing recovery passphrase):

```bash
sudo .venv/bin/python host/esp_key.py enroll /tmp/esp-key-test.img
```

Then unlock with only the C3:

```bash
sudo .venv/bin/python host/esp_key.py unlock /tmp/esp-key-test.img --name esp-key-test
sudo cryptsetup close esp-key-test
```

Verify your recovery passphrase still works **before** trusting even test data.

## Security limitations

v0.1 proves the workflow; it is not a hardened hardware security key. Anyone with sufficient physical access to this development device may be able to extract/replace firmware or stored material. Do not use v0.1 for irreplaceable or high-value data. Hardware-backed provisioning and host/device authentication belong in later versions.
