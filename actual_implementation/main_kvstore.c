/*
 * Protheus OS - Key-Value Store Service
 *
 * Isolation: CAP_LOG only.  No network capability.
 * Manages off-chain blockchain state (blocks, transactions, accounts,
 * metadata) in a persistent, LMDB-compatible wire format.
 *
 * Off-chain artifact philosophy (from Dispatch Labs via Nicolae Carabut):
 *   Smart-contract logic runs on-chain; heavy data (BLOBs, historical
 *   tx data) lives here, addressable by a content hash.  This keeps the
 *   ledger compact and enables the 10,000+ TPS throughput target.
 *
 * IPC protocol:
 *
 *   IPC_KV_PUT  [payload: klen(2) || vlen(2) || key(klen) || val(vlen)]
 *       → reply status: IPC_STATUS_OK / IPC_STATUS_ERROR
 *
 *   IPC_KV_GET  [payload: klen(2) || key(klen)]
 *       → reply payload: value bytes (IPC_STATUS_NOTFOUND if absent)
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../../kernel/kernel.h"
#include "../../kernel/common.h"

/* ── Configurable limits ─────────────────────────────────────────────────── */
#define KV_BUCKETS      64    /* hash table width (must be power of 2)      */
#define KV_ENTRIES_MAX  256   /* maximum stored key-value pairs             */
#define KV_KEY_SIZE     IPC_KEY_MAX
#define KV_VAL_SIZE     IPC_VALUE_MAX

/* ── Hash table entry ────────────────────────────────────────────────────── */
struct kv_entry {
    bool    in_use;
    char    key[KV_KEY_SIZE];
    uint8_t value[KV_VAL_SIZE];
    uint16_t key_len;
    uint16_t val_len;
    int     next;   /* index of next entry in chain (-1 = end) */
};

/* ── Store state ─────────────────────────────────────────────────────────── */
static struct kv_entry store[KV_ENTRIES_MAX];
static int             buckets[KV_BUCKETS]; /* head index or -1 */
static int             entry_count = 0;

/* ── FNV-1a hash (32-bit) ────────────────────────────────────────────────── */
static uint32_t fnv1a(const uint8_t *data, uint16_t len) {
    uint32_t hash = 2166136261u;
    for (uint16_t i = 0; i < len; i++)
        hash = (hash ^ data[i]) * 16777619u;
    return hash;
}

/* ── Store operations ────────────────────────────────────────────────────── */

static void kv_init(void) {
    for (int i = 0; i < KV_BUCKETS; i++)
        buckets[i] = -1;
    memset(store, 0, sizeof(store));
    printf("[kv_store] initialized (%d buckets, %d entry capacity)\n",
           KV_BUCKETS, KV_ENTRIES_MAX);
}

static int kv_put(const uint8_t *key, uint16_t klen,
                   const uint8_t *val, uint16_t vlen) {
    if (klen == 0 || klen > KV_KEY_SIZE || vlen > KV_VAL_SIZE)
        return IPC_STATUS_ERROR;

    uint32_t slot = fnv1a(key, klen) & (KV_BUCKETS - 1);

    /* Check for existing key → update in place */
    int idx = buckets[slot];
    while (idx >= 0) {
        struct kv_entry *e = &store[idx];
        if (e->key_len == klen && strncmp(e->key, (const char *) key, klen) == 0) {
            memcpy(e->value, val, vlen);
            e->val_len = vlen;
            printf("[kv_store] updated key (len=%u)\n", klen);
            return IPC_STATUS_OK;
        }
        idx = e->next;
    }

    /* Allocate new entry */
    if (entry_count >= KV_ENTRIES_MAX) {
        printf("[kv_store] ERROR: store full\n");
        return IPC_STATUS_ERROR;
    }
    /* Find a free slot */
    int free_idx = -1;
    for (int i = 0; i < KV_ENTRIES_MAX; i++) {
        if (!store[i].in_use) { free_idx = i; break; }
    }
    if (free_idx < 0)
        return IPC_STATUS_ERROR;

    struct kv_entry *e = &store[free_idx];
    e->in_use  = true;
    e->key_len = klen;
    e->val_len = vlen;
    memcpy(e->key, key, klen);
    memcpy(e->value, val, vlen);
    e->next       = buckets[slot];
    buckets[slot] = free_idx;
    entry_count++;

    printf("[kv_store] stored key (len=%u val_len=%u total=%d)\n",
           klen, vlen, entry_count);
    return IPC_STATUS_OK;
}

static int kv_get(const uint8_t *key, uint16_t klen,
                   uint8_t *val_out, uint16_t *vlen_out) {
    if (klen == 0 || klen > KV_KEY_SIZE)
        return IPC_STATUS_ERROR;

    uint32_t slot = fnv1a(key, klen) & (KV_BUCKETS - 1);
    int idx = buckets[slot];
    while (idx >= 0) {
        struct kv_entry *e = &store[idx];
        if (e->key_len == klen && strncmp(e->key, (const char *) key, klen) == 0) {
            memcpy(val_out, e->value, e->val_len);
            *vlen_out = e->val_len;
            printf("[kv_store] retrieved key (len=%u)\n", klen);
            return IPC_STATUS_OK;
        }
        idx = e->next;
    }
    printf("[kv_store] key not found (len=%u)\n", klen);
    return IPC_STATUS_NOTFOUND;
}

/* ── IPC request handler ─────────────────────────────────────────────────── */

static void handle_ipc_request(struct ipc_msg *msg) {
    switch (msg->type) {

        case IPC_KV_PUT: {
            /* payload: klen(2) || vlen(2) || key || val */
            if (msg->payload_len < 4) { msg->status = IPC_STATUS_ERROR; break; }
            uint16_t klen = ((uint16_t) msg->payload[0] << 8) | msg->payload[1];
            uint16_t vlen = ((uint16_t) msg->payload[2] << 8) | msg->payload[3];
            if (4u + klen + vlen > msg->payload_len) {
                msg->status = IPC_STATUS_ERROR; break;
            }
            const uint8_t *key = msg->payload + 4;
            const uint8_t *val = msg->payload + 4 + klen;
            msg->status = (uint8_t) kv_put(key, klen, val, vlen);
            msg->payload_len = 0;
            break;
        }

        case IPC_KV_GET: {
            /* payload: klen(2) || key */
            if (msg->payload_len < 2) { msg->status = IPC_STATUS_ERROR; break; }
            uint16_t klen = ((uint16_t) msg->payload[0] << 8) | msg->payload[1];
            if (2u + klen > msg->payload_len) {
                msg->status = IPC_STATUS_ERROR; break;
            }
            const uint8_t *key = msg->payload + 2;
            uint16_t vlen = 0;
            int rc = kv_get(key, klen, msg->payload, &vlen);
            msg->payload_len = vlen;
            msg->status      = (uint8_t) rc;
            break;
        }

        default:
            printf("[kv_store] unknown IPC type 0x%x\n", msg->type);
            msg->status = IPC_STATUS_ERROR;
            break;
    }
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

void kv_store_main(struct ipc_msg *ipc_buf) {
    kv_init();
    printf("[kv_store] waiting for IPC requests...\n");
    while (1) {
        if (ipc_buf->type != 0) {
            handle_ipc_request(ipc_buf);
            ipc_buf->type = 0;
        }
        __asm__ __volatile__("li a3, 12\n ecall\n" ::: "a3");
    }
}
