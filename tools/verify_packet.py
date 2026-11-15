"""
verify_packet.py - Verify and decrypt ONE packet offline (no server needed).

Handy for checking a packet copied from the ESP32 Serial Monitor:
    python tools/verify_packet.py packet.json [--device-keys server/devices.json]
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from securepacket import PacketError, load_device_keys, parse_fields, verify_and_decrypt  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("packet_file")
    ap.add_argument("--device-keys", default=str(ROOT / "server" / "devices.json"))
    args = ap.parse_args()

    packet = json.loads(Path(args.packet_file).read_text())
    devices = load_device_keys(args.device_keys)
    try:
        fields = parse_fields(packet)
        keys = devices[fields["device_id"]]
        reading = verify_and_decrypt(fields, keys["aes_key"], keys["hmac_key"])
    except KeyError:
        print("REJECTED : unknown device"); return 1
    except PacketError as exc:
        print(f"REJECTED : {exc.reason} ({exc})"); return 1
    print("HMAC check : OK (constant-time compare)")
    print(f"Device/seq : {fields['device_id']} / {fields['seq']}")
    print(f"Decrypted  : {reading}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
