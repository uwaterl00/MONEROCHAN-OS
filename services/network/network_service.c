/*
 * Protheus OS — Network Service
 *
 * Isolation: CAP_LOG | CAP_TIMER.
 * No capability to reach crypto_service or kv_store.
 * All data from the wire is untrusted; this service only relays bytes.
 * A full RCE exploit here cannot reach private key material.
 *
 * IPC protocol:
 *
 *   IPC_NET_BROADCAST  [payload: raw TX bytes]
 *       → relays to all active peers; reply: IPC_STATUS_OK
 *
 *   IPC_NET_FETCH_BLOCK []
 *       → returns raw block bytes from best peer; 4-byte big-endian
 *         height prefix followed by block body
 *
 *   IPC_HEARTBEAT      []
 *       → ACK; used by monerod watchdog
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../kernel/kernel.h"
#include "../kernel/common.h"

#define MAX_PEERS       32
#define PEER_ADDR_MAX   48
#define BAN_THRESHOLD   100

struct peer {
    bool     active;
    uint32_t score;          /* ban score; evicted when > BAN_THRESHOLD */
    uint32_t blocks_relayed;
    uint32_t txs_relayed;
    char     address[PEER_ADDR_MAX];
};

static struct peer peers[MAX_PEERS];
static int         peer_count  = 0;
static uint32_t    best_height = 0;    /* reported by peers   */
static uint32_t    local_height = 0;   /* blocks fetched so far */

/* ── Peer management ────────────────────────────────────────────────────── */

static void net_init(void) {
    memset(peers, 0, sizeof(peers));

    /* Monero mainnet seed nodes (production: resolve via DNS or hardcoded IPs) */
    const char *seeds[] = {
        "seeds.moneroseeds.se:18080",
        "seeds.moneroseeds.se2:18080",
        "node.community.rino.io:18081",
        NULL
    };
    for (int i = 0; seeds[i] && peer_count < MAX_PEERS; i++) {
        struct peer *p = &peers[peer_count++];
        p->active = true;
        p->score  = 0;
        strncpy(p->address, seeds[i], PEER_ADDR_MAX - 1);
    }

    /* Approximate Monero mainnet height at time of writing */
    best_height = 3200000;

    printf("[net] init — %d seed peers, chain tip ~%u\n",
           peer_count, best_height);
}

static void net_penalise(int idx, uint32_t penalty) {
    if ((unsigned)idx >= (unsigned)MAX_PEERS) return;
    peers[idx].score += penalty;
    if (peers[idx].score > BAN_THRESHOLD) {
        printf("[net] peer %s banned (score=%u)\n",
               peers[idx].address, peers[idx].score);
        peers[idx].active = false;
    }
}

/* ── TX broadcast ───────────────────────────────────────────────────────── */

static int net_broadcast(const uint8_t *tx, uint16_t tx_len) {
    int sent = 0;
    for (int i = 0; i < peer_count; i++) {
        if (!peers[i].active) continue;
        /*
         * Production: open TCP to peers[i].address, send
         * COMMAND_NOTIFY_NEW_TRANSACTIONS (Monero P2P wire format).
         */
        peers[i].txs_relayed++;
        sent++;
    }
    printf("[net] broadcast %u-byte TX to %d peers\n", tx_len, sent);
    return IPC_STATUS_OK;
}

/* ── Block fetch ────────────────────────────────────────────────────────── */

static int net_fetch_block(uint8_t *out, uint16_t *out_len) {
    /*
     * Production: connect to best peer, issue COMMAND_REQUEST_CHAIN,
     * receive COMMAND_RESPONSE_CHAIN, validate PoW before returning.
     *
     * Stub: generate a deterministic 64-byte block for testing.
     */
    local_height++;

    /* Height as 4-byte big-endian prefix (parsed by monerod) */
    out[0] = (uint8_t)(local_height >> 24);
    out[1] = (uint8_t)(local_height >> 16);
    out[2] = (uint8_t)(local_height >>  8);
    out[3] = (uint8_t)(local_height);

    /* Deterministic filler so monerod can verify consistency */
    for (int i = 4; i < 64; i++)
        out[i] = (uint8_t)((local_height * 7u + (uint32_t)i) & 0xFF);

    *out_len = 64;
    printf("[net] stub block height=%u (%u bytes)\n", local_height, *out_len);
    return IPC_STATUS_OK;
}

/* ── IPC dispatcher ─────────────────────────────────────────────────────── */

static void handle_ipc(struct ipc_msg *msg) {
    switch (msg->type) {

    case IPC_NET_BROADCAST: {
        msg->status      = (uint8_t)net_broadcast(msg->payload, msg->payload_len);
        msg->payload_len = 0;
        break;
    }

    case IPC_NET_FETCH_BLOCK: {
        uint16_t blen = 0;
        msg->status      = (uint8_t)net_fetch_block(msg->payload, &blen);
        msg->payload_len = blen;
        break;
    }

    case IPC_HEARTBEAT:
        msg->status      = IPC_STATUS_OK;
        msg->payload_len = 0;
        break;

    default:
        printf("[net] unknown IPC 0x%x\n", msg->type);
        msg->status = IPC_STATUS_ERROR;
        break;
    }
}

/* ── Entry point ────────────────────────────────────────────────────────── */

void network_service_main(struct ipc_msg *ipc_buf) {
    net_init();
    printf("[net] ready\n");
    while (1) {
        if (ipc_buf->type != 0) {
            handle_ipc(ipc_buf);
            ipc_buf->type = 0;
        }
        __asm__ __volatile__("li a3, %0\n ecall\n" :: "i"(SYS_YIELD) : "a3");
    }
}
