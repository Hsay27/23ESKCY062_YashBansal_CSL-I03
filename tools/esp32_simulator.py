"""
esp32_simulator.py - Behaves exactly like the ESP32 firmware, in Python.

Useful for testing the server without the board, and for the plaintext vs
encrypted comparison in Wireshark.

Usage
  python tools/esp32_simulator.py                       # 5 secure packets
  python tools/esp32_simulator.py --count 20 --interval 2
  python tools/esp32_simulator.py --plain               # INSECURE baseline
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from securepacket import build_packet, load_device_keys  # noqa: E402

STATE_FILE = Path(__file__).resolve().parent / ".sim_seq.json"  # like ESP32 NVS


def load_seq(device_id):
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text()).get(device_id, 0)
    return 0


def save_seq(device_id, seq):
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    state[device_id] = seq
    STATE_FILE.write_text(json.dumps(state))


class FakeDHT22:
    """Slowly drifting temperature/humidity, like a real room."""
    def __init__(self):
        self.t, self.h = 27.0, 50.0

    def read(self):
        self.t = min(max(self.t + random.uniform(-0.3, 0.3), 15), 40)
        self.h = min(max(self.h + random.uniform(-1.0, 1.0), 20), 90)
        return round(self.t, 2), round(self.h, 2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="http://127.0.0.1:5000")
    p.add_argument("--device", default="ESP32-01")
    p.add_argument("--keys", default=str(ROOT / "server" / "devices.json"))
    p.add_argument("--count", type=int, default=5)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--plain", action="store_true", help="send UNENCRYPTED (demo)")
    args = p.parse_args()

    keys = load_device_keys(args.keys)[args.device]
    sensor, seq = FakeDHT22(), load_seq(args.device)
    print(f"[SIM] device={args.device} server={args.server} start_seq={seq}")

    for _ in range(args.count):
        temp, hum = sensor.read()
        reading = {"temp_c": temp, "humidity": hum, "ts": int(time.time())}

        if args.plain:
            url = args.server + "/api/v1/telemetry/plain"
            body = {"device_id": args.device, "reading": reading}
            print(f"[SIM] PLAINTEXT -> {json.dumps(body)}")
        else:
            seq += 1
            save_seq(args.device, seq)          # persist before sending
            url = args.server + "/api/v1/telemetry"
            t0 = time.perf_counter()
            body = build_packet(args.device, seq, reading, keys["aes_key"], keys["hmac_key"])
            took = (time.perf_counter() - t0) * 1e6
            print(f"[SIM] seq={seq} reading={json.dumps(reading)}")
            print(f"      iv ={body['iv']}")
            print(f"      ct ={body['ct']}")
            print(f"      mac={body['mac']}  (encrypt+sign {took:.0f} us)")

        try:
            r = requests.post(url, json=body, timeout=5)
            print(f"      HTTP {r.status_code} {r.text.strip()}")
        except requests.RequestException as exc:
            print(f"      send failed: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
