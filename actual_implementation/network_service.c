/*
 * Protheus OS - Network Service
 *
 * Isolation: CAP_LOG | CAP_TIMER only.
 * No capability to call crypto_service or kv_store directly.
 * All data it processes is untrusted external input.
 *
 * This is intentionally the "dumb" component: it neither understands
 * transaction semantics nor holds any key material.  Its sole function
 * is to relay raw bytes between the P2P peer pool and the monerod
 * orchestrator.  Even a successful remote-code-execution exploit here
 * cannot access private keys — the attacker is trapped in this sandbox.
 *
 * IPC protocol:
 *
 *   IPC_NET_BROADCAST   [payload: raw TX bytes]
 *       → broadcasts to all connected peers
 *       → reply: IPC_STATUS_OK
 *
 *   IPC_NET_FETCH_BLOCK []
 *       → fetches latest block from best peer
 *       → reply payload: raw block bytes
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */

#include "../../kernel/kernel.h"
#include "../../kernel/common.h"

/* ── Simulated peer pool ─────────────────────────────────────────────────── */
#define MAX_PEERS        32
#define PEER_ADDR_SIZE   48

struct peer {
    bool   active;
    char   address[PEER_ADDR_SIZE];  /* e.g. "192.168.1.42:18080" */
    uint32_t score;                  /* ban score; 0=trusted */
    uint32_t blocks_relayed;
    uint32_t txs_relayed;
};

static struct peer peers[MAX_PEERS];
static int peer_count = 0;

/* Simulated chain height seen from peers */
static uint32_t best_height   = 0;
static uint32_t local_height  = 0;

/* ── Peer management ─────────────────────────────────────────────────────── */

static void net_init(void) {
    memset(peers, 0, sizeof(peers));

    /* Seed with Monero mainnet bootstrap nodes (placeholders) */
    const char *seed_nodes[] = {
        "seeds.moneroseeds.se:18080",
        "seeds.moneroseeds.se2:18080",
        "node.community.rino.io:18081",
        NULL
    };
    for (int i = 0; seed_nodes[i]; i++) {
        struct peer *p = &peers[peer_count++];
        p->active  = true;
        p->score   = 0;
        strncpy(p->address, seed_nodes[i], PEER_ADDR_SIZE - 1);
    }

    best_height = 3200000;  /* Approximate Monero mainnet height at code time */

    printf("[network_service] initialized with %d seed peers\n", peer_count);
    printf("[network_service] reported chain height: %u\n", best_height);
}

static void net_ban_peer(int idx, uint32_t penalty) {
    if (idx < 0 || idx >= MAX_PEERS) return;
    peers[idx].score += penalty;
    if (peers[idx].score > 100) {
        printf("[network_service] peer %s banned (score=%u)\n",
               peers[idx].address, peers[idx].score);
        peers[idx].active = false;
    }
}

/* ── TX broadcasting ─────────────────────────────────────────────────────── */

static int net_broadcast_tx(const uint8_t *tx_data, uint16_t tx_len) {
    int sent = 0;
    for (int i = 0; i < peer_count; i++) {
        if (!peers[i].active) continue;
        /* In a full implementation: open TCP socket to peers[i].address,
         * send a Monero P2P COMMAND_NOTIFY_NEW_TRANSACTIONS packet. */
        peers[i].txs_relayed++;
        sent++;
    }
    printf("[network_service] broadcast %u-byte TX to %d peers\n",
           tx_len, sent);
    return IPC_STATUS_OK;
}

/* ── Block fetching ──────────────────────────────────────────────────────── */

static int net_fetch_block(uint8_t *block_out, uint16_t *block_len_out) {
    /*
     * Construct a minimal stub block at current best_height + 1.
     * A production implementation connects to the best peer and issues a
     * COMMAND_REQUEST_CHAIN → COMMAND_RESPONSE_CHAIN exchange.
     */
    local_height++;

    /* Encode height as a 4-byte big-endian prefix followed by a "block hash" */
    block_out[0] = (uint8_t)(local_height >> 24);
    block_out[1] = (uint8_t)(local_height >> 16);
    block_out[2] = (uint8_t)(local_height >>  8);
    block_out[3] = (uint8_t)(local_height);

    /* Fill the rest with deterministic pseudodata (height ^ pattern) */
    for (int i = 4; i < 64; i++)
        block_out[i] = (uint8_t)((local_height * 7 + i) & 0xFF);

    *block_len_out = 64;
    printf("[network_service] fetched stub block height=%u (%u bytes)\n",
           local_height, *block_len_out);
    return IPC_STATUS_OK;
}

/* ── IPC request handler ─────────────────────────────────────────────────── */

static void handle_ipc_request(struct ipc_msg *msg) {
    switch (msg->type) {

        case IPC_NET_BROADCAST: {
            int rc = net_broadcast_tx(msg->payload, msg->payload_len);
            msg->status      = (uint8_t) rc;
            msg->payload_len = 0;
            break;
        }

        case IPC_NET_FETCH_BLOCK: {
            uint16_t blen = 0;
            int rc = net_fetch_block(msg->payload, &blen);
            msg->payload_len = blen;
            msg->status      = (uint8_t) rc;
            break;
        }

        case IPC_HEARTBEAT:
            /* Acknowledge heartbeat from parent watchdog */
            msg->status      = IPC_STATUS_OK;
            msg->payload_len = 0;
            break;

        default:
            printf("[network_service] unknown IPC type 0x%x\n", msg->type);
            msg->status = IPC_STATUS_ERROR;
            break;
    }
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

void network_service_main(struct ipc_msg *ipc_buf) {
    net_init();
    printf("[network_service] waiting for IPC requests...\n");
    while (1) {
        if (ipc_buf->type != 0) {
            handle_ipc_request(ipc_buf);
            ipc_buf->type = 0;
        }
        __asm__ __volatile__("li a3, 12\n ecall\n" ::: "a3");
    }
}
