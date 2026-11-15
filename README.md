# Secure Sensor Data Transmission (ESP32 -> Server)

Project code: CSL-I03 | Yash Bansal (23ESKCY062) | CS-IOT-A-G2
Cyber Security Lab (7CS4-22), SKIT Jaipur | Linked experiment: Exp 8

An ESP32 reads a DHT22 sensor, encrypts each reading with AES-128-CBC
(random IV per message), signs it with HMAC-SHA256 (Encrypt-then-MAC) and
sends it to a Flask server. The server verifies the HMAC, blocks replays
using a sequence counter, decrypts, validates and stores the reading in
SQLite. Rejected requests are logged and shown on a dashboard.

## Folder structure

    securepacket.py                 shared packet format (encrypt/sign/verify)
    server/app.py                   Flask server + dashboard
    server/storage.py               SQLite storage, atomic replay check
    server/devices.json             pre-shared keys per device
    server/templates/dashboard.html dashboard page
    firmware/esp32_secure_sensor/   Arduino sketch for the ESP32
        esp32_secure_sensor.ino
        secure_packet.h             AES + HMAC with mbedTLS
        secrets.h                   Wi-Fi, server URL, keys
    tools/esp32_simulator.py        same protocol in Python (no board needed)
    tools/attack_tests.py           14 attack / security test cases
    tools/benchmark.py              size and time overhead + graphs
    tools/keygen.py                 generate new keys for a device
    tests/test_securepacket.py      unit tests

## Setup (laptop)

    pip install -r requirements.txt
    python -m unittest -v tests/test_securepacket.py
    python server/app.py                   # dashboard at http://127.0.0.1:5000

## Run with the simulator

    python tools/esp32_simulator.py --count 10
    python tools/attack_tests.py
    python tools/benchmark.py

## Run with the real ESP32

1. Laptop and ESP32 on YOUR OWN mobile hotspot / home router (not college Wi-Fi).
2. Find the laptop IP (`ipconfig` / `ip a`) and put it in `SERVER_URL` in secrets.h.
3. Put the hotspot name and password in secrets.h.
4. Arduino IDE: install the ESP32 board package and "DHT sensor library"
   (Adafruit). Board = ESP32 Dev Module, Serial Monitor at 115200 baud.
5. Wiring: DHT22 VCC -> 3V3, DATA -> GPIO4 (10k pull-up), GND -> GND.
   No sensor? Set `USE_FAKE_SENSOR 1`.
6. Start `python server/app.py`, upload the sketch, watch Serial Monitor
   and the dashboard. Allow port 5000 in the laptop firewall if needed.

## Wireshark comparison (plain vs secure)

    python server/app.py --allow-plain
    python tools/esp32_simulator.py --plain --count 3   # readable in Wireshark
    python tools/esp32_simulator.py --count 3           # only ciphertext visible

Wireshark filter: `tcp.port == 5000 && http` (use the Loopback adapter
when the simulator runs on the same laptop).

## New keys

    python tools/keygen.py ESP32-01     # updates devices.json, prints C arrays

If the ESP32 flash is erased its counter restarts at 1 and the server will
reject packets as replays. Delete server/data/sensor.db (or create new keys)
to reset.

## Ethics

All testing is done only on the author's own laptop, ESP32 and hotspot,
using dummy sensor data.
