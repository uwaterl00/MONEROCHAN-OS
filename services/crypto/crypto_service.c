/*
 * Protheus OS — Crypto Service
 *
 * Isolation: CAP_LOG only.  No network route.  No storage writes.
 * Private key material lives exclusively in this process's address space.
 *
 * IPC protocol (kernel writes to ipc_buf->payload, clears type on reply):
 *
 *   IPC_CRYPTO_HASH   [payload: raw bytes]
 *       → reply payload: 32-byte SHA-256 digest
 *
 *   IPC_CRYPTO_SIGN   [payload: message bytes]
 *       → reply payload: 64-byte Ed25519 signature
 *
 *   IPC_CRYPTO_VERIFY [payload: pubkey(32) || sig(64) || message]
 *       → reply payload: uint8_t 1=valid / 0=invalid
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../kernel/kernel.h"
#include "../kernel/common.h"
#include "../crypto/sha256.h"
#include "../crypto/ed25519.h"

/* ── Key material (placeholder seed — replace with TRNG/TPM in production) */
static const uint8_t KEY_SEED[ED25519_SEED_SIZE] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11
};

static uint8_t g_priv[ED25519_PRIVATE_KEY_SIZE];
static uint8_t g_pub [ED25519_PUBLIC_KEY_SIZE];
static bool    g_init = false;

static void crypto_init(void) {
    if (g_init) return;
    ed25519_generate_keypair(KEY_SEED, g_priv, g_pub);
    printf("[crypto] init — pubkey[0..3]: %x %x %x %x\n",
           g_pub[0], g_pub[1], g_pub[2], g_pub[3]);
    g_init = true;
}

/* ── IPC dispatcher ─────────────────────────────────────────────────────── */

static void handle_ipc(struct ipc_msg *msg) {
    switch (msg->type) {

    case IPC_CRYPTO_HASH: {
        if (msg->payload_len == 0) { msg->status = IPC_STATUS_ERROR; break; }
        uint8_t digest[SHA256_DIGEST_SIZE];
        sha256(msg->payload, msg->payload_len, digest);
        memcpy(msg->payload, digest, SHA256_DIGEST_SIZE);
        msg->payload_len = SHA256_DIGEST_SIZE;
        msg->status      = IPC_STATUS_OK;
        break;
    }

    case IPC_CRYPTO_SIGN: {
        if (msg->payload_len == 0) { msg->status = IPC_STATUS_ERROR; break; }
        uint8_t sig[ED25519_SIGNATURE_SIZE];
        ed25519_sign(msg->payload, msg->payload_len, g_priv, sig);
        memcpy(msg->payload, sig, ED25519_SIGNATURE_SIZE);
        msg->payload_len = ED25519_SIGNATURE_SIZE;
        msg->status      = IPC_STATUS_OK;
        break;
    }

    case IPC_CRYPTO_VERIFY: {
        uint16_t min = ED25519_PUBLIC_KEY_SIZE + ED25519_SIGNATURE_SIZE;
        if (msg->payload_len < min) { msg->status = IPC_STATUS_ERROR; break; }
        const uint8_t *pk  = msg->payload;
        const uint8_t *sig = msg->payload + ED25519_PUBLIC_KEY_SIZE;
        const uint8_t *m   = sig + ED25519_SIGNATURE_SIZE;
        uint16_t mlen      = msg->payload_len - min;
        msg->payload[0]    = (uint8_t)ed25519_verify(m, mlen, pk, sig);
        msg->payload_len   = 1;
        msg->status        = IPC_STATUS_OK;
        break;
    }

    default:
        printf("[crypto] unknown IPC type 0x%x\n", msg->type);
        msg->status = IPC_STATUS_ERROR;
        break;
    }
}

/* ── Entry point ────────────────────────────────────────────────────────── */

void crypto_service_main(struct ipc_msg *ipc_buf) {
    crypto_init();
    printf("[crypto] ready\n");
    while (1) {
        if (ipc_buf->type != 0) {
            handle_ipc(ipc_buf);
            ipc_buf->type = 0;  /* signal handled */
        }
        __asm__ __volatile__("li a3, %0\n ecall\n" :: "i"(SYS_YIELD) : "a3");
    }
}
