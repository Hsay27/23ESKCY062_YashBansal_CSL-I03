"""
keygen.py - Generate a fresh AES-128 key and HMAC-SHA256 key for a device.

The keys are written to server/devices.json (server side) and printed as C
arrays to paste into firmware/esp32_secure_sensor/secrets.h (device side).
Both sides must hold the SAME keys (pre-shared symmetric keys).

Usage:  python tools/keygen.py ESP32-01
"""

import argparse
import json
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEVICES_FILE = ROOT / "server" / "devices.json"


def c_array(name, data):
    body = ", ".join(f"0x{b:02X}" for b in data)
    return f"static const uint8_t {name}[{len(data)}] = {{ {body} }};"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("device_id")
    args = parser.parse_args()

    aes_key = secrets.token_bytes(16)    # cryptographically secure random
    hmac_key = secrets.token_bytes(32)

    devices = json.loads(DEVICES_FILE.read_text()) if DEVICES_FILE.exists() else {}
    devices[args.device_id] = {"aes_key": aes_key.hex(), "hmac_key": hmac_key.hex()}
    DEVICES_FILE.write_text(json.dumps(devices, indent=2) + "\n")
    print(f"[+] Saved keys for {args.device_id} in {DEVICES_FILE}")
    print("[+] Paste these lines into secrets.h:\n")
    print(f'#define DEVICE_ID "{args.device_id}"')
    print(c_array("AES_KEY", aes_key))
    print(c_array("HMAC_KEY", hmac_key))


if __name__ == "__main__":
    main()
