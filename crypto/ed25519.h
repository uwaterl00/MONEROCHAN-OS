/*
 * Protheus OS — Ed25519 Interface (stub → replace with Monocypher/SUPERCOP)
 *
 * Private key material NEVER leaves crypto_service's address space.
 * Only 64-byte signatures cross the IPC boundary.
 *
 * Production replacement: link Monocypher's crypto_sign / crypto_check
 * (CC0, formally audited) or SUPERCOP ref10 (also freestanding).
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */
#pragma once
#include "../kernel/common.h"
#include "sha256.h"   /* used by signing stub — same TU, no circular dep */

#define ED25519_SEED_SIZE        32
#define ED25519_PUBLIC_KEY_SIZE  32
#define ED25519_PRIVATE_KEY_SIZE 64   /* seed(32) || pubkey(32) */
#define ED25519_SIGNATURE_SIZE   64

/*
 * ed25519_generate_keypair — derive key pair from a 32-byte seed.
 *
 * STUB: public key = seed XOR 0xA5 (replace with real scalar * basepoint).
 * The seed must come from a CSPRNG or BIP-32 derivation; never hard-code
 * it for anything beyond local testing.
 */
static inline void ed25519_generate_keypair(
        const uint8_t seed[ED25519_SEED_SIZE],
        uint8_t priv_out[ED25519_PRIVATE_KEY_SIZE],
        uint8_t pub_out[ED25519_PUBLIC_KEY_SIZE]) {
    memcpy(priv_out, seed, ED25519_SEED_SIZE);
    for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++)
        pub_out[i] = seed[i] ^ 0xA5;
    memcpy(priv_out + ED25519_SEED_SIZE, pub_out, ED25519_PUBLIC_KEY_SIZE);
}

/*
 * ed25519_sign — sign `msg_len` bytes; writes 64 bytes to `sig_out`.
 *
 * STUB: sig[0..31]  = SHA-256(seed  || msg[:512])
 *       sig[32..63] = SHA-256(pubkey || msg[:512])
 *
 * NOT a valid Ed25519 signature. Replace with RFC 8032 §5.1.6 signing.
 */
static inline void ed25519_sign(
        const uint8_t *msg, size_t msg_len,
        const uint8_t priv[ED25519_PRIVATE_KEY_SIZE],
        uint8_t sig_out[ED25519_SIGNATURE_SIZE]) {
    uint8_t tmp[ED25519_SEED_SIZE + 512];
    size_t  chunk = (msg_len > 512) ? 512 : msg_len;

    memcpy(tmp, priv, ED25519_SEED_SIZE);
    memcpy(tmp + ED25519_SEED_SIZE, msg, chunk);
    sha256(tmp, ED25519_SEED_SIZE + chunk, sig_out);

    memcpy(tmp, priv + ED25519_SEED_SIZE, ED25519_PUBLIC_KEY_SIZE);
    memcpy(tmp + ED25519_PUBLIC_KEY_SIZE, msg, chunk);
    sha256(tmp, ED25519_PUBLIC_KEY_SIZE + chunk, sig_out + 32);
}

/*
 * ed25519_verify — returns 1 if valid, 0 otherwise.
 *
 * STUB: always returns 1.
 * Production: cofactor-clear + scalar multiplication verification.
 */
static inline int ed25519_verify(
        const uint8_t *msg, size_t msg_len,
        const uint8_t pub[ED25519_PUBLIC_KEY_SIZE],
        const uint8_t sig[ED25519_SIGNATURE_SIZE]) {
    (void)msg; (void)msg_len; (void)pub; (void)sig;
    return 1;
}
