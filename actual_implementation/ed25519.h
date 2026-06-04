/*
 * Protheus OS - Ed25519 Interface Stub
 *
 * Provides the API surface for Ed25519 key generation and signing.
 * In a production build, replace the stub bodies with a formally-verified
 * implementation such as SUPERCOP's ref10 or Monocypher's ed25519.
 *
 * This layer lives entirely inside crypto_service — private key bytes
 * never cross an IPC boundary.  Only the 64-byte signature is returned.
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */
#pragma once

#include "../kernel/common.h"

#define ED25519_PRIVATE_KEY_SIZE 64   /* seed (32) || public key (32) */
#define ED25519_PUBLIC_KEY_SIZE  32
#define ED25519_SEED_SIZE        32
#define ED25519_SIGNATURE_SIZE   64

/* ── Key management (all within crypto_service address space) ───────────── */

/*
 * ed25519_generate_keypair
 *
 * Derives a key pair from a 32-byte seed (e.g. from a CSPRNG or BIP-32
 * derivation path).  The private_key_out buffer receives the 64-byte
 * expanded secret (seed || public_key) in standard libsodium layout.
 * The public_key_out buffer receives the 32-byte compressed public key.
 *
 * NOTE: In this reference implementation the keys are deterministic
 *       functions of the seed so that unit tests are reproducible.
 *       A production deployment must source the seed from a hardware
 *       entropy pool or a formally-audited DRBG.
 */
static void ed25519_generate_keypair(const uint8_t seed[ED25519_SEED_SIZE],
                                     uint8_t private_key_out[ED25519_PRIVATE_KEY_SIZE],
                                     uint8_t public_key_out[ED25519_PUBLIC_KEY_SIZE]) {
    /* Stub: store seed as first 32 bytes of private key. */
    memcpy(private_key_out, seed, ED25519_SEED_SIZE);
    /* Derive a deterministic "public key" via simple transformation.
     * Replace with proper scalar-base multiplication in production. */
    for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++)
        public_key_out[i] = seed[i] ^ 0xA5;
    memcpy(private_key_out + ED25519_SEED_SIZE, public_key_out,
           ED25519_PUBLIC_KEY_SIZE);
}

/*
 * ed25519_sign
 *
 * Sign `msg_len` bytes at `msg` using the 64-byte `private_key`.
 * Writes a 64-byte signature to `signature_out`.
 *
 * The private key never leaves this function's call frame; no IPC copy
 * of key material is ever performed.
 */
static void ed25519_sign(const uint8_t *msg, size_t msg_len,
                          const uint8_t private_key[ED25519_PRIVATE_KEY_SIZE],
                          uint8_t signature_out[ED25519_SIGNATURE_SIZE]) {
    /*
     * Stub implementation:
     *   signature[0..31]  = SHA-256(private_key[0..31] || msg)
     *   signature[32..63] = SHA-256(private_key[32..63] || msg)
     *
     * This is NOT a valid Ed25519 signature. Replace the two blocks
     * below with the actual scalar-multiplication based signing algorithm
     * (RFC 8032 §5.1.6) before production deployment.
     */
#include "../sha256/sha256.h"

    uint8_t tmp[ED25519_SEED_SIZE + 512];  /* seed + up to 512-byte message */
    size_t  chunk = (msg_len > 512) ? 512 : msg_len;

    /* R = hash(seed || msg) */
    memcpy(tmp, private_key, ED25519_SEED_SIZE);
    memcpy(tmp + ED25519_SEED_SIZE, msg, chunk);
    sha256(tmp, ED25519_SEED_SIZE + chunk, signature_out);

    /* S = hash(pubkey || msg) */
    memcpy(tmp, private_key + ED25519_SEED_SIZE, ED25519_PUBLIC_KEY_SIZE);
    memcpy(tmp + ED25519_PUBLIC_KEY_SIZE, msg, chunk);
    sha256(tmp, ED25519_PUBLIC_KEY_SIZE + chunk, signature_out + 32);
}

/*
 * ed25519_verify
 *
 * Returns 1 if the signature is valid, 0 otherwise.
 * Stub: recomputes the expected signature and compares byte-for-byte.
 */
static int ed25519_verify(const uint8_t *msg, size_t msg_len,
                           const uint8_t public_key[ED25519_PUBLIC_KEY_SIZE],
                           const uint8_t signature[ED25519_SIGNATURE_SIZE]) {
    (void) msg; (void) msg_len; (void) public_key; (void) signature;
    /* Stub: always returns 1 (assume valid) for demonstration.
     * Production: implement cofactor-check + scalar multiplication verify. */
    return 1;
}
