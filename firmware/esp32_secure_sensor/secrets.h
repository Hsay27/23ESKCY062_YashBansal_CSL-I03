/*
 * secrets.h - Wi-Fi details, server address and the PRE-SHARED KEYS.
 *
 * The keys below must be identical to the "ESP32-01" entry in
 * server/devices.json. To make new keys run:  python tools/keygen.py ESP32-01
 * and paste the printed lines here.
 *
 * Use your OWN hotspot / home router - never the college network.
 * Never upload a real secrets.h to GitHub.
 */
#pragma once
#include <stdint.h>

#define WIFI_SSID   "YOUR_HOTSPOT_NAME"
#define WIFI_PASS   "YOUR_HOTSPOT_PASSWORD"

// IP address of the laptop running server/app.py (find it with ipconfig / ip a)
#define SERVER_URL  "http://192.168.43.100:5000/api/v1/telemetry"

#define DEVICE_ID   "ESP32-01"

// 128-bit AES key (encryption)
static const uint8_t AES_KEY[16] = {
  0xA3, 0x09, 0xDB, 0xD7, 0x2C, 0xC9, 0x7C, 0xBB,
  0xC5, 0x58, 0xB4, 0x8F, 0xBF, 0xBF, 0x7C, 0x6F
};

// 256-bit HMAC key (authentication / integrity) - different from AES key
static const uint8_t HMAC_KEY[32] = {
  0xC8, 0x91, 0xCB, 0xAF, 0x83, 0xD8, 0x7C, 0x8C,
  0x47, 0xE1, 0xCD, 0xF8, 0x1E, 0x85, 0xF2, 0xBF,
  0x00, 0x08, 0xF0, 0x61, 0x79, 0xE0, 0xA0, 0xA8,
  0xFC, 0xA8, 0xA6, 0x1F, 0xE2, 0x3D, 0x61, 0xE6
};
