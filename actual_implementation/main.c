/*
 * Protheus OS - Cryptographic Service
 *
 * Isolation: CAP_LOG only.  No network route.  No storage write.
 * Private key material lives exclusively in this process's address space.
 *
 * IPC protocol (received in ipc_buf->payload):
 *
 *   IPC_CRYPTO_HASH    [payload: raw bytes]
 *       → reply payload: 32-byte SHA-256 digest
 *
 *   IPC_CRYPTO_SIGN    [payload: message bytes]
 *       → reply payload: 64-byte Ed25519 signature
 *
 *   IPC_CRYPTO_VERIFY  [payload: pubkey(32) || sig(64) || message]
 *       → reply payload: uint8_t 1=valid / 0=invalid
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../../kernel/kernel.h"
#include "../../kernel/common.h"
#include "../../src/lib/sha256/sha256.h"
#include "../../src/lib/ed25519/ed25519.h"

/* ── Private key material (NEVER leaves this process) ────────────────────── */
/*
 * In a real deployment this seed comes from:
 *   1. A hardware entropy source (TRNG / TPM)
 *   2. A BIP-39 mnemonic stored in encrypted flash
 *   3. A key-derivation-function output from a user passphrase
 *
 * The 32-byte seed below is a placeholder for testing purposes ONLY.
 */
static const uint8_t KEY_SEED[ED25519_SEED_SIZE] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11
};

static uint8_t g_private_key[ED25519_PRIVATE_KEY_SIZE];
static uint8_t g_public_key[ED25519_PUBLIC_KEY_SIZE];
static bool    g_initialized = false;

static void crypto_init(void) {
    if (g_initialized) return;
    ed25519_generate_keypair(KEY_SEED, g_private_key, g_public_key);
    printf("[crypto_service] initialized. public key: ");
    for (int i = 0; i < 8; i++)
        printf("%x", g_public_key[i]);
    printf("...\n");
    g_initialized = true;
}

/* ── IPC request dispatcher ──────────────────────────────────────────────── */

static void handle_ipc_request(struct ipc_msg *msg) {
    switch (msg->type) {

        case IPC_CRYPTO_HASH: {
            if (msg->payload_len == 0) {
                msg->status = IPC_STATUS_ERROR;
                break;
            }
            uint8_t digest[SHA256_DIGEST_SIZE];
            sha256(msg->payload, msg->payload_len, digest);
            memcpy(msg->payload, digest, SHA256_DIGEST_SIZE);
            msg->payload_len = SHA256_DIGEST_SIZE;
            msg->status      = IPC_STATUS_OK;
            printf("[crypto_service] hash computed (%u bytes in)\n",
                   msg->payload_len);
            break;
        }

        case IPC_CRYPTO_SIGN: {
            if (msg->payload_len == 0) {
                msg->status = IPC_STATUS_ERROR;
                break;
            }
            uint8_t sig[ED25519_SIGNATURE_SIZE];
            ed25519_sign(msg->payload, msg->payload_len,
                          g_private_key, sig);
            memcpy(msg->payload, sig, ED25519_SIGNATURE_SIZE);
            msg->payload_len = ED25519_SIGNATURE_SIZE;
            msg->status      = IPC_STATUS_OK;
            printf("[crypto_service] signed %u-byte payload\n",
                   msg->payload_len);
            break;
        }

        case IPC_CRYPTO_VERIFY: {
            /* payload layout: pubkey(32) || sig(64) || message */
            if (msg->payload_len < ED25519_PUBLIC_KEY_SIZE + ED25519_SIGNATURE_SIZE) {
                msg->status = IPC_STATUS_ERROR;
                break;
            }
            const uint8_t *pk  = msg->payload;
            const uint8_t *sig = msg->payload + ED25519_PUBLIC_KEY_SIZE;
            const uint8_t *m   = msg->payload + ED25519_PUBLIC_KEY_SIZE
                                              + ED25519_SIGNATURE_SIZE;
            uint16_t m_len = msg->payload_len
                           - ED25519_PUBLIC_KEY_SIZE
                           - ED25519_SIGNATURE_SIZE;
            int valid = ed25519_verify(m, m_len, pk, sig);
            msg->payload[0]  = (uint8_t) valid;
            msg->payload_len = 1;
            msg->status      = IPC_STATUS_OK;
            printf("[crypto_service] verify result: %d\n", valid);
            break;
        }

        default:
            printf("[crypto_service] unknown IPC type 0x%x\n", msg->type);
            msg->status = IPC_STATUS_ERROR;
            break;
    }
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

void crypto_service_main(struct ipc_msg *ipc_buf) {
    crypto_init();
    printf("[crypto_service] waiting for IPC requests...\n");
    while (1) {
        /* Block until the kernel delivers a request */
        /* (In RISC-V bare-metal model: spin-yield) */
        if (ipc_buf->type != 0) {
            handle_ipc_request(ipc_buf);
            ipc_buf->type = 0;   /* mark handled */
        }
        /* Yield CPU back to scheduler */
        __asm__ __volatile__("li a3, 12\n ecall\n" ::: "a3");
    }
}
