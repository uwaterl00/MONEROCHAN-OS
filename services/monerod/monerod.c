/*
 * Protheus OS — Monero Daemon Orchestrator (monerod)
 *
 * Isolation: CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK | CAP_TIMER | CAP_LOG
 *
 * The only process with a capability route to all three services.
 * Dataflow:
 *   network_service ──(raw block/TX)──► monerod
 *   monerod ──(hash/sign)────────────► crypto_service
 *   monerod ──(store block)──────────► kv_store
 *   monerod ──(broadcast signed TX)──► network_service
 *
 * An attacker who fully compromises network_service is confined — it holds
 * CAP_LOG | CAP_TIMER only and has no path to crypto_service or kv_store.
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../kernel/kernel.h"
#include "../kernel/common.h"

/* ── Inline syscall wrappers ────────────────────────────────────────────── */
/*
 * RISC-V ecall ABI: syscall number in a3, arguments in a0–a2 (and a4 for
 * SYS_KV_PUT vlen).  Return value in a0.
 *
 * Note: "i" constraint is used for the immediate syscall constant.
 * GCC/Clang RISC-V accept this; the register clobber list is explicit.
 */

static inline int sys_crypto_hash(const uint8_t *data, uint16_t len,
                                    uint8_t *out) {
    register long a0 __asm__("a0") = (long)data;
    register long a1 __asm__("a1") = (long)len;
    register long a2 __asm__("a2") = (long)out;
    register long a3 __asm__("a3") = SYS_CRYPTO_HASH;
    __asm__ __volatile__("ecall"
        : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3) : "memory");
    return (int)a0;
}

static inline int sys_crypto_sign(const uint8_t *payload, uint16_t len,
                                    uint8_t *sig_out) {
    register long a0 __asm__("a0") = (long)payload;
    register long a1 __asm__("a1") = (long)len;
    register long a2 __asm__("a2") = (long)sig_out;
    register long a3 __asm__("a3") = SYS_CRYPTO_SIGN;
    __asm__ __volatile__("ecall"
        : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3) : "memory");
    return (int)a0;
}

static inline int sys_kv_put(const char *key, uint16_t klen,
                               const uint8_t *val, uint16_t vlen) {
    register long a0 __asm__("a0") = (long)key;
    register long a1 __asm__("a1") = (long)klen;
    register long a2 __asm__("a2") = (long)val;
    register long a3 __asm__("a3") = SYS_KV_PUT;
    register long a4 __asm__("a4") = (long)vlen;
    __asm__ __volatile__("ecall"
        : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4) : "memory");
    return (int)a0;
}

static inline int sys_kv_get(const char *key, uint16_t klen, uint8_t *out) {
    register long a0 __asm__("a0") = (long)key;
    register long a1 __asm__("a1") = (long)klen;
    register long a2 __asm__("a2") = (long)out;
    register long a3 __asm__("a3") = SYS_KV_GET;
    __asm__ __volatile__("ecall"
        : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3) : "memory");
    return (int)a0;
}

static inline int sys_net_broadcast(const uint8_t *tx, uint16_t len) {
    register long a0 __asm__("a0") = (long)tx;
    register long a1 __asm__("a1") = (long)len;
    register long a3 __asm__("a3") = SYS_NET_BROADCAST;
    __asm__ __volatile__("ecall"
        : "+r"(a0) : "r"(a1), "r"(a3) : "memory");
    return (int)a0;
}

static inline int sys_net_fetch(uint8_t *block_out) {
    register long a0 __asm__("a0") = (long)block_out;
    register long a3 __asm__("a3") = SYS_NET_FETCH;
    __asm__ __volatile__("ecall"
        : "+r"(a0) : "r"(a3) : "memory");
    return (int)a0;
}

static inline void sys_yield(void) {
    register long a3 __asm__("a3") = SYS_YIELD;
    __asm__ __volatile__("ecall" :: "r"(a3) : "memory");
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

static const char HEX[] = "0123456789abcdef";

/* Encode `len` bytes of `src` as hex into `dst` (needs dst[len*2+1]) */
static void hex_encode(const uint8_t *src, int len, char *dst) {
    for (int i = 0; i < len; i++) {
        dst[i*2]     = HEX[(src[i] >> 4) & 0xF];
        dst[i*2 + 1] = HEX[ src[i]       & 0xF];
    }
    dst[len * 2] = '\0';
}

/* Encode a uint32_t as decimal into buf; returns buf */
static char *u32_to_dec(uint32_t v, char *buf, int buflen) {
    buf[--buflen] = '\0';
    if (!v) { buf[--buflen] = '0'; return &buf[buflen]; }
    while (v && buflen > 0) { buf[--buflen] = '0' + (v % 10); v /= 10; }
    return &buf[buflen];
}

/* ── Chain state ────────────────────────────────────────────────────────── */

static uint32_t chain_height     = 0;
static uint32_t pending_tx_count = 0;
static uint8_t  last_block_hash[IPC_HASH_LEN];

/* ── Block processing ───────────────────────────────────────────────────── */

static void process_new_block(void) {
    uint8_t raw[IPC_VALUE_MAX];
    int blen = sys_net_fetch(raw);
    if (blen <= 0) { printf("[monerod] net fetch failed (%d)\n", blen); return; }

    /* Hash the block */
    uint8_t hash[IPC_HASH_LEN];
    int hlen = sys_crypto_hash(raw, (uint16_t)blen, hash);
    if (hlen != IPC_HASH_LEN) {
        printf("[monerod] hash failed (%d)\n", hlen); return;
    }

    /* Store block by hash */
    char key[IPC_HASH_LEN * 2 + 1];
    hex_encode(hash, IPC_HASH_LEN, key);
    int rc = sys_kv_put(key, (uint16_t)(IPC_HASH_LEN * 2), raw, (uint16_t)blen);
    if (rc != IPC_STATUS_OK) {
        printf("[monerod] kv_put failed (%d)\n", rc); return;
    }

    memcpy(last_block_hash, hash, IPC_HASH_LEN);
    chain_height = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16)
                 | ((uint32_t)raw[2] <<  8) |  (uint32_t)raw[3];

    printf("[monerod] block height=%u hash=%.8s...\n", chain_height, key);
}

/* ── Transaction submission ─────────────────────────────────────────────── */

static uint32_t tx_seq = 0;

static void submit_tx(const char *tx_desc) {
    uint16_t tlen = (uint16_t)strlen(tx_desc);

    /* Hash */
    uint8_t tx_hash[IPC_HASH_LEN];
    if (sys_crypto_hash((const uint8_t *)tx_desc, tlen, tx_hash) != IPC_HASH_LEN) {
        printf("[monerod] tx hash failed\n"); return;
    }

    /* Sign */
    uint8_t sig[64];
    int slen = sys_crypto_sign(tx_hash, IPC_HASH_LEN, sig);
    if (slen <= 0) { printf("[monerod] tx sign failed\n"); return; }

    /* Store in mempool: key "mp:<seq>" */
    char mk[16] = "mp:";
    char num[12]; u32_to_dec(tx_seq, num, sizeof(num));
    /* Append decimal seq to mk */
    int mi = 3;
    for (char *p = num; *p && mi < 15; ) mk[mi++] = *p++;
    mk[mi] = '\0';
    sys_kv_put(mk, (uint16_t)mi, sig, (uint16_t)slen);

    /* Broadcast */
    int rc = sys_net_broadcast(sig, (uint16_t)slen);
    printf("[monerod] TX seq=%u broadcast rc=%d\n", tx_seq, rc);
    tx_seq++;
    pending_tx_count++;
}

/* ── Main loop ──────────────────────────────────────────────────────────── */

void monerod_main(void) {
    printf("\n[monerod] starting — CRYPTO | KVSTORE | NETWORK\n");

    /* Smoke-test crypto_service */
    const char *probe = "Protheus-OS-init";
    uint8_t     phash[IPC_HASH_LEN];
    int plen = sys_crypto_hash((const uint8_t *)probe, (uint16_t)strlen(probe), phash);
    if (plen == IPC_HASH_LEN)
        printf("[monerod] crypto reachable — hash[0]=0x%x\n", phash[0]);
    else
        printf("[monerod] WARNING: crypto unreachable\n");

    uint32_t cycle = 0;
    while (1) {
        printf("\n[monerod] cycle %u ──────────────────\n", cycle);

        process_new_block();

        /* Submit a demo TX every 5 cycles */
        if (cycle % 5 == 0) {
            char tx[80];
            const char *pfx = "TX:TRANSFER:5XMR:WALLET_A:CYCLE:";
            int i = 0;
            while (pfx[i]) { tx[i] = pfx[i]; i++; }
            char cnum[12]; char *cp = u32_to_dec(cycle, cnum, sizeof(cnum));
            while (*cp && i < 79) tx[i++] = *cp++;
            tx[i] = '\0';
            submit_tx(tx);
        }

        /* Update chain tip record */
        uint8_t hb[4] = {
            (uint8_t)(chain_height >> 24),
            (uint8_t)(chain_height >> 16),
            (uint8_t)(chain_height >>  8),
            (uint8_t)(chain_height)
        };
        sys_kv_put("chain:tip:height", 16, hb, 4);

        printf("[monerod] height=%u pending_tx=%u\n", chain_height, pending_tx_count);

        /* Cooperative sleep: yield 500 times (~5s at ~100 yields/s) */
        for (int s = 0; s < 500; s++) sys_yield();
        cycle++;
    }
}
