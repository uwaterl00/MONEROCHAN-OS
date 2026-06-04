/*
 * Protheus OS - Monero Daemon Orchestrator (monerod)
 *
 * Isolation: CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK | CAP_TIMER | CAP_LOG
 * This is the only process that can speak to all three services.
 * It acts as the sole traffic cop between the isolation boundaries:
 *
 *   network_service ──(raw block/TX data)──► monerod
 *   monerod ────────(hash/sign request)────► crypto_service
 *   monerod ────────(store block data)─────► kv_store
 *   monerod ────────(broadcast signed TX)──► network_service
 *
 * The network_service has NO capability route to crypto_service.
 * An attacker who fully compromises network_service is confined to
 * that sandbox with no path to private key material.
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../../kernel/kernel.h"
#include "../../kernel/common.h"

/* ── Blockchain state ────────────────────────────────────────────────────── */

static uint32_t chain_height     = 0;
static uint32_t pending_tx_count = 0;
static uint8_t  last_block_hash[IPC_HASH_LEN];

/* ── Syscall wrappers (thin shims over the kernel's ecall ABI) ───────────── */

static int sys_crypto_hash(const uint8_t *data, uint16_t len,
                            uint8_t *hash_out) {
    int ret;
    __asm__ __volatile__(
        "mv a0, %[data]\n"
        "mv a1, %[len]\n"
        "mv a2, %[out]\n"
        "li a3, %[sysno]\n"
        "ecall\n"
        "mv %[ret], a0\n"
        : [ret]  "=r"(ret)
        : [data] "r"(data), [len] "r"((uint32_t) len),
          [out]  "r"(hash_out), [sysno] "i"(SYS_CRYPTO_HASH)
        : "a0", "a1", "a2", "a3"
    );
    return ret;
}

static int sys_crypto_sign(const uint8_t *payload, uint16_t len,
                            uint8_t *sig_out) {
    int ret;
    __asm__ __volatile__(
        "mv a0, %[data]\n"
        "mv a1, %[len]\n"
        "mv a2, %[out]\n"
        "li a3, %[sysno]\n"
        "ecall\n"
        "mv %[ret], a0\n"
        : [ret]  "=r"(ret)
        : [data] "r"(payload), [len] "r"((uint32_t) len),
          [out]  "r"(sig_out), [sysno] "i"(SYS_CRYPTO_SIGN)
        : "a0", "a1", "a2", "a3"
    );
    return ret;
}

static int sys_kv_put(const char *key, uint16_t klen,
                       const uint8_t *val, uint16_t vlen) {
    int ret;
    __asm__ __volatile__(
        "mv a0, %[key]\n"
        "mv a1, %[klen]\n"
        "mv a2, %[val]\n"
        "li a3, %[sysno]\n"
        "mv a4, %[vlen]\n"
        "ecall\n"
        "mv %[ret], a0\n"
        : [ret]   "=r"(ret)
        : [key]   "r"(key),   [klen]  "r"((uint32_t) klen),
          [val]   "r"(val),   [vlen]  "r"((uint32_t) vlen),
          [sysno] "i"(SYS_KV_PUT)
        : "a0", "a1", "a2", "a3", "a4"
    );
    return ret;
}

static int sys_kv_get(const char *key, uint16_t klen,
                       uint8_t *val_out) {
    int ret;
    __asm__ __volatile__(
        "mv a0, %[key]\n"
        "mv a1, %[klen]\n"
        "mv a2, %[out]\n"
        "li a3, %[sysno]\n"
        "ecall\n"
        "mv %[ret], a0\n"
        : [ret]   "=r"(ret)
        : [key]   "r"(key),  [klen] "r"((uint32_t) klen),
          [out]   "r"(val_out), [sysno] "i"(SYS_KV_GET)
        : "a0", "a1", "a2", "a3"
    );
    return ret;
}

static int sys_net_broadcast(const uint8_t *tx, uint16_t len) {
    int ret;
    __asm__ __volatile__(
        "mv a0, %[tx]\n"
        "mv a1, %[len]\n"
        "li a3, %[sysno]\n"
        "ecall\n"
        "mv %[ret], a0\n"
        : [ret]   "=r"(ret)
        : [tx]    "r"(tx), [len] "r"((uint32_t) len),
          [sysno] "i"(SYS_NET_BROADCAST)
        : "a0", "a1", "a3"
    );
    return ret;
}

static int sys_net_fetch(uint8_t *block_out) {
    int ret;
    __asm__ __volatile__(
        "mv a0, %[out]\n"
        "li a3, %[sysno]\n"
        "ecall\n"
        "mv %[ret], a0\n"
        : [ret]   "=r"(ret)
        : [out]   "r"(block_out), [sysno] "i"(SYS_NET_FETCH)
        : "a0", "a3"
    );
    return ret;
}

static void sys_yield(void) {
    __asm__ __volatile__("li a3, 12\n ecall\n" ::: "a3");
}

/* ── Block processing cycle ──────────────────────────────────────────────── */

static void process_new_block(void) {
    uint8_t raw_block[IPC_VALUE_MAX];
    int block_len = sys_net_fetch(raw_block);
    if (block_len <= 0) {
        printf("[monerod] net fetch failed (%d)\n", block_len);
        return;
    }

    /* Step 1: Hash the raw block */
    uint8_t block_hash[IPC_HASH_LEN];
    int hash_len = sys_crypto_hash(raw_block, (uint16_t) block_len, block_hash);
    if (hash_len != IPC_HASH_LEN) {
        printf("[monerod] block hash failed (%d)\n", hash_len);
        return;
    }

    /* Step 2: Persist block to kv_store under its hash as key */
    char hash_key[IPC_HASH_LEN * 2 + 1];
    for (int i = 0; i < IPC_HASH_LEN; i++) {
        static const char hex[] = "0123456789abcdef";
        hash_key[i * 2]     = hex[(block_hash[i] >> 4) & 0xF];
        hash_key[i * 2 + 1] = hex[block_hash[i] & 0xF];
    }
    hash_key[IPC_HASH_LEN * 2] = '\0';

    int rc = sys_kv_put(hash_key, IPC_HASH_LEN * 2,
                         raw_block, (uint16_t) block_len);
    if (rc != IPC_STATUS_OK) {
        printf("[monerod] kv_put failed (%d)\n", rc);
        return;
    }

    /* Update chain tip */
    memcpy(last_block_hash, block_hash, IPC_HASH_LEN);
    chain_height = ((uint32_t) raw_block[0] << 24)
                 | ((uint32_t) raw_block[1] << 16)
                 | ((uint32_t) raw_block[2] <<  8)
                 | ((uint32_t) raw_block[3]);

    printf("[monerod] accepted block height=%u hash=%c%c%c%c...\n",
           chain_height,
           hash_key[0], hash_key[1], hash_key[2], hash_key[3]);
}

static void submit_transaction(const char *tx_desc) {
    /* Step 1: Hash the transaction payload */
    uint8_t tx_hash[IPC_HASH_LEN];
    int hash_len = sys_crypto_hash(
        (const uint8_t *) tx_desc, (uint16_t) strlen(tx_desc), tx_hash);
    if (hash_len != IPC_HASH_LEN) {
        printf("[monerod] tx hash failed\n");
        return;
    }

    /* Step 2: Sign the hash */
    uint8_t tx_sig[64];
    int sig_len = sys_crypto_sign(tx_hash, IPC_HASH_LEN, tx_sig);
    if (sig_len <= 0) {
        printf("[monerod] tx sign failed\n");
        return;
    }

    /* Step 3: Store the signed TX in kv_store (mempool) */
    static uint32_t tx_seq = 0;
    char mempool_key[32];
    mempool_key[0] = 'm'; mempool_key[1] = 'p'; mempool_key[2] = ':';
    /* Encode sequence number */
    mempool_key[3] = '0' + (tx_seq / 1000) % 10;
    mempool_key[4] = '0' + (tx_seq / 100)  % 10;
    mempool_key[5] = '0' + (tx_seq / 10)   % 10;
    mempool_key[6] = '0' + (tx_seq)         % 10;
    mempool_key[7] = '\0';
    tx_seq++;

    sys_kv_put(mempool_key, (uint16_t) strlen(mempool_key),
               tx_sig, (uint16_t) sig_len);

    /* Step 4: Broadcast the signed transaction */
    int brc = sys_net_broadcast(tx_sig, (uint16_t) sig_len);
    if (brc == IPC_STATUS_OK)
        printf("[monerod] TX broadcast (%u bytes, seq=%u)\n", sig_len, tx_seq - 1);
    else
        printf("[monerod] TX broadcast failed (rc=%d)\n", brc);

    pending_tx_count++;
}

/* ── Main orchestration loop ─────────────────────────────────────────────── */

void monerod_main(void) {
    printf("\n[monerod] Protheus blockchain orchestrator starting...\n");
    printf("[monerod] capability mask includes: CRYPTO | KVSTORE | NETWORK\n");

    /* Verify services are reachable with a test hash */
    const char *test_input = "Protheus-OS-init";
    uint8_t     test_hash[IPC_HASH_LEN];
    int         tlen = sys_crypto_hash((const uint8_t *) test_input,
                                        (uint16_t) strlen(test_input),
                                        test_hash);
    if (tlen == IPC_HASH_LEN) {
        printf("[monerod] crypto_service reachable (hash[0]=0x%x)\n",
               test_hash[0]);
    } else {
        printf("[monerod] WARNING: crypto_service unreachable\n");
    }

    uint32_t cycle = 0;
    while (1) {
        printf("\n[monerod] ── cycle %u ─────────────────────\n", cycle);

        /* Phase A: Sync latest block from network */
        process_new_block();

        /* Phase B: Submit a demo transaction every 5 cycles */
        if (cycle % 5 == 0) {
            char tx[80];
            /* Build a minimal "transfer" string for demo purposes */
            const char *prefix = "TX:TRANSFER:5XMR:WALLET_A:CYCLE:";
            int i = 0;
            while (prefix[i]) { tx[i] = prefix[i]; i++; }
            tx[i++] = '0' + (cycle / 10) % 10;
            tx[i++] = '0' + cycle % 10;
            tx[i]   = '\0';
            submit_transaction(tx);
        }

        /* Phase C: Update chain-tip record in kv_store */
        uint8_t height_bytes[4];
        height_bytes[0] = (uint8_t)(chain_height >> 24);
        height_bytes[1] = (uint8_t)(chain_height >> 16);
        height_bytes[2] = (uint8_t)(chain_height >>  8);
        height_bytes[3] = (uint8_t)(chain_height);
        sys_kv_put("chain:tip:height", 16, height_bytes, 4);

        printf("[monerod] height=%u pending_tx=%u\n",
               chain_height, pending_tx_count);

        /* Sleep ~5 seconds (yield repeatedly) */
        for (int s = 0; s < 500; s++)
            sys_yield();

        cycle++;
    }
}
