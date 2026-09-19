# esp-key

Experimental XIAO ESP32-C3 possession key for unlocking **LUKS2** volumes.

> **v0.1 is a prototype. Use only disposable/test data.** The device secret is stored in ESP32 NVS and is not yet protected with Secure Boot, flash encryption, eFuse HMAC, PIN entry, or a trusted display.

## What v0.1 does

The C3 owns a random 256-bit device secret. For each LUKS volume, the host derives a deterministic challenge from the volume UUID and asks the C3 for HMAC-SHA256. The host then derives a separate 256-bit LUKS key from that response.

The device secret never crosses USB. A normal recovery passphrase remains in a separate LUKS keyslot.

The host stages derived key material in an anonymous Linux `memfd`, so LUKS enrollment can keep the existing recovery-passphrase prompt attached to the terminal instead of trying to use stdin for two different keys.

## Firmware

Requires PlatformIO:

```bash
cd firmware
pio run
pio run -t upload
```

A normal firmware upload preserves the existing NVS secret. The newer firmware also migrates the original v0.1 secret by marking it initialized rather than generating a replacement.

**Important:** after enrolling a volume, do not run `pio run -t erase`, `esptool erase_flash`, or otherwise erase NVS unless you are intentionally destroying this ESP-Key identity. Your recovery passphrase is what saves you if the device secret is lost.

## Host setup

Requires Python 3, `pyserial`, and `cryptsetup`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r host/requirements.txt
python host/esp_key.py status
```

If autodetection finds multiple ESP-Key devices, select one explicitly:

```bash
python host/esp_key.py --port /dev/ttyACM0 status
```

The host probes candidate ESP serial ports and only accepts devices that answer the ESP-Key protocol and report healthy secret storage.

## Safe v0.1 test

Create a disposable 64 MiB image and initialize it with a recovery passphrase:

```bash
truncate -s 64M /tmp/esp-key-test.img
sudo cryptsetup luksFormat --type luks2 /tmp/esp-key-test.img
```

Verify that recovery passphrase first:

```bash
sudo cryptsetup open --test-passphrase /tmp/esp-key-test.img
```

Check the C3:

```bash
python host/esp_key.py status
```

You can safely compare deterministic derivation without printing the raw LUKS key:

```bash
python host/esp_key.py fingerprint test-vault
python host/esp_key.py fingerprint test-vault
```

Both fingerprints should match.

Enroll the C3 into a new LUKS keyslot. `cryptsetup` will ask for the existing recovery passphrase interactively:

```bash
sudo .venv/bin/python host/esp_key.py enroll /tmp/esp-key-test.img
```

A successful enrollment ends with:

```text
ESP-Key keyslot enrolled and verified.
```

Then unlock with the physical C3:

```bash
sudo .venv/bin/python host/esp_key.py unlock /tmp/esp-key-test.img --name esp-key-test
sudo cryptsetup close esp-key-test
```

Unplugging the C3 should make a fresh ESP-Key unlock impossible, while the original recovery passphrase should still work.

## Tests

Host tests use Python's standard `unittest` framework:

```bash
python -m unittest discover -s tests -v
```

They cover deterministic derivation, in-memory key staging, actual buffer zeroization, and the LUKS enrollment/unlock command paths that previously conflicted over stdin.

## Raw key output

The CLI refuses to dump raw derived key material unless explicitly requested:

```bash
python host/esp_key.py key test-vault --unsafe
```

Normal testing should use `fingerprint` instead.

## Security limitations

v0.1 proves the workflow; it is **not** a hardened hardware security key.

- The master secret currently lives in ordinary ESP32 NVS and can be at risk from a sufficiently capable physical attacker.
- There is no user-presence button or PIN yet; possession of the powered device is enough to request HMAC operations.
- Secure Boot, flash encryption, and eFuse-backed HMAC are intentionally not enabled yet because irreversible eFuse changes should only happen after the basic design is proven.
- Losing or erasing the C3 secret makes its LUKS keyslot unusable. Keep and verify a separate recovery passphrase.
- Do not use v0.1 for irreplaceable or high-value data.

A later hardware-backed version should move the secret behind the ESP32-C3's security hardware and add stronger device/host policy without changing the recovery-key principle.
