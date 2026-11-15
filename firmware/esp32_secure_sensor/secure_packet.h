/*
 * secure_packet.h - builds the encrypted + signed packet on the ESP32.
 *
 * Uses only mbedTLS, which is already built into the ESP32 Arduino core
 * (and uses the ESP32's hardware AES / SHA accelerators).
 *
 *   ct  = AES-128-CBC(AES_KEY, iv, PKCS7(plaintext_json))
 *   mac = HMAC-SHA256(HMAC_KEY, "device_id|seq|base64(iv)|base64(ct)")
 *   out = {"device_id":..,"seq":..,"iv":..,"ct":..,"mac":..}
 *
 * Must match securepacket.py on the server byte for byte.
 */
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"

#define SP_IV_LEN       16
#define SP_MAX_PLAIN    128                       // plaintext JSON limit
#define SP_MAX_CT       (SP_MAX_PLAIN + 16)       // + up to one padding block
#define SP_B64_LEN(n)   ((((n) + 2) / 3) * 4 + 1) // base64 size incl. '\0'
#define SP_MAX_PACKET   512

/* AES-128-CBC encrypt with PKCS#7 padding.
 * Returns the ciphertext length, or -1 on error. */
static int sp_aes128_cbc_encrypt(const uint8_t key[16],
                                 const uint8_t iv[SP_IV_LEN],
                                 const uint8_t *plain, size_t plainLen,
                                 uint8_t *out, size_t outSize) {
  size_t padLen = 16 - (plainLen % 16);  // PKCS#7 adds 1..16 bytes
  size_t total = plainLen + padLen;
  if (total > outSize || total > SP_MAX_CT) return -1;

  uint8_t buf[SP_MAX_CT];
  memcpy(buf, plain, plainLen);
  memset(buf + plainLen, (int)padLen, padLen); // pad byte = pad length

  uint8_t ivCopy[SP_IV_LEN];
  memcpy(ivCopy, iv, SP_IV_LEN);  // mbedtls overwrites the IV buffer

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  int rc = mbedtls_aes_setkey_enc(&ctx, key, 128);
  if (rc == 0)
    rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, total,
                               ivCopy, buf, out);
  mbedtls_aes_free(&ctx);
  memset(buf, 0, sizeof(buf));     // do not leave plaintext in RAM
  return rc == 0 ? (int)total : -1;
}

/* HMAC-SHA256 of a text message, written as 64 lowercase hex chars + '\0'. */
static bool sp_hmac_sha256_hex(const uint8_t *key, size_t keyLen,
                               const char *msg, char hexOut[65]) {
  uint8_t mac[32];
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (info == NULL) return false;
  if (mbedtls_md_hmac(info, key, keyLen, (const unsigned char *)msg, strlen(msg), mac) != 0)
    return false;
  for (int i = 0; i < 32; i++) snprintf(hexOut + 2 * i, 3, "%02x", mac[i]);
  hexOut[64] = '\0';
  return true;
}

/* Binary -> base64 text ('\0' terminated). */
static bool sp_base64(const uint8_t *in, size_t len, char *out, size_t outSize) {
  size_t olen = 0;
  if (mbedtls_base64_encode((unsigned char *)out, outSize, &olen, in, len) != 0) return false;
  out[olen] = '\0';
  return true;
}

/* Build the complete JSON packet into `out`.
 * Returns the packet length, or -1 on any error. */
static int sp_build_packet(const char *deviceId, uint32_t seq,
                           const char *plainJson,
                           const uint8_t aesKey[16],
                           const uint8_t *hmacKey, size_t hmacKeyLen,
                           const uint8_t iv[SP_IV_LEN],
                           char *out, size_t outSize) {
  uint8_t ct[SP_MAX_CT];
  int ctLen = sp_aes128_cbc_encrypt(aesKey, iv,
                                    (const uint8_t *)plainJson,
                                    strlen(plainJson), ct, sizeof(ct));
  if (ctLen < 0) return -1;

  char ivB64[SP_B64_LEN(SP_IV_LEN)];
  char ctB64[SP_B64_LEN(SP_MAX_CT)];
  if (!sp_base64(iv, SP_IV_LEN, ivB64, sizeof(ivB64))) return -1;
  if (!sp_base64(ct, (size_t)ctLen, ctB64, sizeof(ctB64))) return -1;

  // The signed string: device_id|seq|iv|ct  (Encrypt-then-MAC)
  char macInput[400];
  int n = snprintf(macInput, sizeof(macInput), "%s|%lu|%s|%s",
                   deviceId, (unsigned long)seq, ivB64, ctB64);
  if (n < 0 || n >= (int)sizeof(macInput)) return -1;

  char macHex[65];
  if (!sp_hmac_sha256_hex(hmacKey, hmacKeyLen, macInput, macHex))
    return -1;

  n = snprintf(out, outSize,
               "{\"device_id\":\"%s\",\"seq\":%lu,\"iv\":\"%s\","
               "\"ct\":\"%s\",\"mac\":\"%s\"}",
               deviceId, (unsigned long)seq, ivB64, ctB64, macHex);
  if (n < 0 || n >= (int)outSize) return -1;
  return n;
}
