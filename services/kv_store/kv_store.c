/*
 * Protheus OS — Key-Value Store Service
 *
 * Isolation: CAP_LOG only.  No network capability.
 *
 * Manages off-chain blockchain state (blocks, transactions, mempool,
 * chain metadata) in an in-process FNV-1a hash table.
 *
 * Wire protocol (all fields big-endian):
 *
 *   IPC_KV_PUT  payload: klen(2) || vlen(2) || key(klen) || val(vlen)
 *       → status: IPC_STATUS_OK | IPC_STATUS_ERROR
 *
 *   IPC_KV_GET  payload: klen(2) || key(klen)
 *       → reply payload: value bytes; status IPC_STATUS_NOTFOUND if absent
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../kernel/kernel.h"
#include "../kernel/common.h"

#define KV_BUCKETS     64    /* must be power-of-2 */
#define KV_ENTRIES_MAX 256

struct kv_entry {
    bool     in_use;
    uint16_t key_len;
    uint16_t val_len;
    int      next;           /* chaining index, -1 = end */
    char     key[IPC_KEY_MAX];
    uint8_t  value[IPC_VALUE_MAX];
};

static struct kv_entry store[KV_ENTRIES_MAX];
static int             buckets[KV_BUCKETS];
static int             entry_count = 0;

/* FNV-1a 32-bit */
static uint32_t fnv1a(const uint8_t *data, uint16_t len) {
    uint32_t h = 2166136261u;
    for (uint16_t i = 0; i < len; i++)
        h = (h ^ data[i]) * 16777619u;
    return h;
}

static void kv_init(void) {
    for (int i = 0; i < KV_BUCKETS; i++) buckets[i] = -1;
    memset(store, 0, sizeof(store));
    for (int i = 0; i < KV_ENTRIES_MAX; i++) store[i].next = -1;
    printf("[kv_store] init — %d buckets, %d capacity\n",
           KV_BUCKETS, KV_ENTRIES_MAX);
}

static int kv_put(const uint8_t *key, uint16_t klen,
                   const uint8_t *val, uint16_t vlen) {
    if (!klen || klen > IPC_KEY_MAX || vlen > IPC_VALUE_MAX)
        return IPC_STATUS_ERROR;

    uint32_t slot = fnv1a(key, klen) & (KV_BUCKETS - 1);

    /* Update in-place if key exists */
    for (int idx = buckets[slot]; idx >= 0; idx = store[idx].next) {
        struct kv_entry *e = &store[idx];
        if (e->key_len == klen && strncmp(e->key, (const char *)key, klen) == 0) {
            memcpy(e->value, val, vlen);
            e->val_len = vlen;
            return IPC_STATUS_OK;
        }
    }

    /* Allocate */
    if (entry_count >= KV_ENTRIES_MAX) {
        printf("[kv_store] full\n");
        return IPC_STATUS_ERROR;
    }
    int fi = -1;
    for (int i = 0; i < KV_ENTRIES_MAX; i++)
        if (!store[i].in_use) { fi = i; break; }
    if (fi < 0) return IPC_STATUS_ERROR;

    struct kv_entry *e = &store[fi];
    e->in_use  = true;
    e->key_len = klen;
    e->val_len = vlen;
    memcpy(e->key,   key, klen);
    memcpy(e->value, val, vlen);
    e->next       = buckets[slot];
    buckets[slot] = fi;
    entry_count++;
    return IPC_STATUS_OK;
}

static int kv_get(const uint8_t *key, uint16_t klen,
                   uint8_t *val_out, uint16_t *vlen_out) {
    if (!klen || klen > IPC_KEY_MAX) return IPC_STATUS_ERROR;
    uint32_t slot = fnv1a(key, klen) & (KV_BUCKETS - 1);
    for (int idx = buckets[slot]; idx >= 0; idx = store[idx].next) {
        struct kv_entry *e = &store[idx];
        if (e->key_len == klen && strncmp(e->key, (const char *)key, klen) == 0) {
            memcpy(val_out, e->value, e->val_len);
            *vlen_out = e->val_len;
            return IPC_STATUS_OK;
        }
    }
    return IPC_STATUS_NOTFOUND;
}

/* ── IPC dispatcher ─────────────────────────────────────────────────────── */

static void handle_ipc(struct ipc_msg *msg) {
    switch (msg->type) {

    case IPC_KV_PUT: {
        if (msg->payload_len < 4) { msg->status = IPC_STATUS_ERROR; break; }
        uint16_t klen = ((uint16_t)msg->payload[0] << 8) | msg->payload[1];
        uint16_t vlen = ((uint16_t)msg->payload[2] << 8) | msg->payload[3];
        if ((uint32_t)4 + klen + vlen > msg->payload_len) {
            msg->status = IPC_STATUS_ERROR; break;
        }
        msg->status      = (uint8_t)kv_put(msg->payload + 4,       klen,
                                             msg->payload + 4 + klen, vlen);
        msg->payload_len = 0;
        break;
    }

    case IPC_KV_GET: {
        if (msg->payload_len < 2) { msg->status = IPC_STATUS_ERROR; break; }
        uint16_t klen = ((uint16_t)msg->payload[0] << 8) | msg->payload[1];
        if ((uint32_t)2 + klen > msg->payload_len) {
            msg->status = IPC_STATUS_ERROR; break;
        }
        uint16_t vlen = 0;
        int rc = kv_get(msg->payload + 2, klen, msg->payload, &vlen);
        msg->payload_len = vlen;
        msg->status      = (uint8_t)rc;
        break;
    }

    default:
        printf("[kv_store] unknown IPC 0x%x\n", msg->type);
        msg->status = IPC_STATUS_ERROR;
        break;
    }
}

/* ── Entry point ────────────────────────────────────────────────────────── */

void kv_store_main(struct ipc_msg *ipc_buf) {
    kv_init();
    printf("[kv_store] ready\n");
    while (1) {
        if (ipc_buf->type != 0) {
            handle_ipc(ipc_buf);
            ipc_buf->type = 0;
        }
        __asm__ __volatile__("li a3, %0\n ecall\n" :: "i"(SYS_YIELD) : "a3");
    }
}
