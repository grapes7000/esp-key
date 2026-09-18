#!/usr/bin/env python3
import argparse, hashlib, hmac, os, subprocess, sys, time
import serial
from serial.tools import list_ports

DOMAIN=b"esp-key/luks/v0.1\x00"

def find_port(explicit=None):
    if explicit: return explicit
    for p in list_ports.comports():
        if "303A" in (p.hwid or "").upper() or "ESP" in (p.description or "").upper():
            return p.device
    raise RuntimeError("ESP-Key not found; use --port /dev/ttyACM0")

def talk(ser, line):
    ser.write((line+"\n").encode()); ser.flush()
    deadline=time.time()+3
    while time.time()<deadline:
        r=ser.readline().decode(errors="replace").strip()
        if not r or r.startswith("READY "): continue
        return r
    raise RuntimeError("ESP-Key timed out")

def connect(port=None):
    s=serial.Serial(find_port(port),115200,timeout=.3)
    time.sleep(1.5); s.reset_input_buffer()
    if not talk(s,"PING").startswith("OK "): raise RuntimeError("Not an ESP-Key")
    return s

def derive(ser, context):
    # Deterministic challenge binds this key to a specific LUKS UUID/context.
    challenge=hashlib.sha256(DOMAIN+context.encode()).digest()
    r=talk(ser,"HMAC "+challenge.hex())
    if not r.startswith("HMAC "): raise RuntimeError(r)
    raw=bytes.fromhex(r.split()[1])
    # Separate the LUKS key from the raw device response.
    return hmac.new(raw, DOMAIN+b"key", hashlib.sha256).digest()

def luks_uuid(dev):
    r=subprocess.run(["cryptsetup","luksUUID",dev],capture_output=True,text=True)
    if r.returncode: raise RuntimeError(r.stderr.strip() or "Not a LUKS volume")
    return r.stdout.strip()

def cmd_status(a):
    with connect(a.port) as s:
        print(talk(s,"ID")); print("OK ESP-KEY/0.1")

def cmd_key(a):
    with connect(a.port) as s: sys.stdout.buffer.write(derive(s,a.context))

def cmd_unlock(a):
    uuid=luks_uuid(a.device)
    with connect(a.port) as s: key=derive(s,"luks:"+uuid)
    try:
        r=subprocess.run(["cryptsetup","open","--key-file=-",a.device,a.name],input=key)
    finally:
        key=b"\0"*len(key)
    raise SystemExit(r.returncode)

def cmd_enroll(a):
    uuid=luks_uuid(a.device)
    print("This adds ESP-Key as a NEW LUKS keyslot; your existing recovery passphrase stays intact.")
    with connect(a.port) as s: key=derive(s,"luks:"+uuid)
    try:
        r=subprocess.run(["cryptsetup","luksAddKey",a.device,"--new-keyfile=-"],input=key)
    finally:
        key=b"\0"*len(key)
    raise SystemExit(r.returncode)

def main():
    p=argparse.ArgumentParser(prog="esp-key"); p.add_argument("--port")
    sp=p.add_subparsers(required=True)
    q=sp.add_parser("status"); q.set_defaults(fn=cmd_status)
    q=sp.add_parser("key"); q.add_argument("context"); q.set_defaults(fn=cmd_key)
    q=sp.add_parser("enroll"); q.add_argument("device"); q.set_defaults(fn=cmd_enroll)
    q=sp.add_parser("unlock"); q.add_argument("device"); q.add_argument("--name",default="esp-key-vault"); q.set_defaults(fn=cmd_unlock)
    a=p.parse_args()
    try:a.fn(a)
    except (RuntimeError,serial.SerialException) as e: print("esp-key:",e,file=sys.stderr); raise SystemExit(1)
if __name__=="__main__": main()
