#pragma once
/*
 * Protheus OS - Kernel Definitions
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * RISC-V rv32ima, SV32 paging, OpenSBI console, VirtIO block device.
 * The kernel enforces strict isolation between:
 *   crypto_service  - holds key material; no network access
 *   kv_store        - persistent off-chain state; no network access
 *   network_service - P2P layer; no direct crypto access
 *   monerod         - orchestrator; routes between the above
 */
#include "common.h"

/* ── Process / scheduler ─────────────────────────────────────────────────── */
#define PROCS_MAX   16         /* max concurrent processes                   */
#define PROC_UNUSED  0
#define PROC_RUNNABLE 1
#define PROC_BLOCKED  2        /* waiting on IPC                             */
#define PROC_EXITED   3

/* Capability bitmask – each bit grants access to one service.
 * A process with CAP_CRYPTO cannot call network_service directly, etc.
 * Assigned by the kernel at process creation from init.config.           */
#define CAP_NONE       0x00
#define CAP_CRYPTO     (1 << 0)   /* may call crypto_service RPC            */
#define CAP_KVSTORE    (1 << 1)   /* may call kv_store RPC                  */
#define CAP_NETWORK    (1 << 2)   /* may call network_service RPC           */
#define CAP_TIMER      (1 << 3)   /* may use timer                          */
#define CAP_LOG        (1 << 4)   /* may write to logger                    */
#define CAP_ALL        0xFF

/* IPC message types */
#define IPC_CRYPTO_HASH      0x01
#define IPC_CRYPTO_SIGN      0x02
#define IPC_CRYPTO_VERIFY    0x03
#define IPC_KV_PUT           0x10
#define IPC_KV_GET           0x11
#define IPC_NET_BROADCAST    0x20
#define IPC_NET_FETCH_BLOCK  0x21
#define IPC_HEARTBEAT        0xFF

#define IPC_STATUS_OK        0
#define IPC_STATUS_DENIED    1   /* capability check failed                 */
#define IPC_STATUS_ERROR     2   /* service-level error                     */
#define IPC_STATUS_NOTFOUND  3

/* IPC message buffer sizes */
#define IPC_KEY_MAX    64
#define IPC_VALUE_MAX  512
#define IPC_HASH_LEN   32   /* SHA-256 digest length (bytes)               */
#define IPC_SIG_LEN    64   /* Ed25519 signature length (bytes)             */

/* ── RISC-V SV32 paging ──────────────────────────────────────────────────── */
#define SATP_SV32     (1u << 31)
#define SSTATUS_SPIE  (1 << 5)
#define SSTATUS_SUM   (1 << 18)
#define SCAUSE_ECALL  8

#define PAGE_V  (1 << 0)
#define PAGE_R  (1 << 1)
#define PAGE_W  (1 << 2)
#define PAGE_X  (1 << 3)
#define PAGE_U  (1 << 4)

#define USER_BASE 0x1000000

/* ── Filesystem / disk ───────────────────────────────────────────────────── */
#define FILES_MAX         8          /* increased from 2 for multiple services */
#define FILE_DATA_MAX     4096       /* maximum bytes per file entry           */
#define SECTOR_SIZE       512
#define DISK_MAX_SIZE     align_up(sizeof(struct file) * FILES_MAX, SECTOR_SIZE)

/* ── VirtIO block ─────────────────────────────────────────────────────────── */
#define VIRTQ_ENTRY_NUM   16
#define VIRTIO_DEVICE_BLK 2
#define VIRTIO_BLK_PADDR  0x10001000

#define VIRTIO_REG_MAGIC         0x00
#define VIRTIO_REG_VERSION       0x04
#define VIRTIO_REG_DEVICE_ID     0x08
#define VIRTIO_REG_PAGE_SIZE     0x28
#define VIRTIO_REG_QUEUE_SEL     0x30
#define VIRTIO_REG_QUEUE_NUM_MAX 0x34
#define VIRTIO_REG_QUEUE_NUM     0x38
#define VIRTIO_REG_QUEUE_PFN     0x40
#define VIRTIO_REG_QUEUE_NOTIFY  0x50
#define VIRTIO_REG_DEVICE_STATUS 0x70
#define VIRTIO_REG_DEVICE_CONFIG 0x100

#define VIRTIO_STATUS_ACK        1
#define VIRTIO_STATUS_DRIVER     2
#define VIRTIO_STATUS_DRIVER_OK  4

#define VIRTQ_DESC_F_NEXT           1
#define VIRTQ_DESC_F_WRITE          2
#define VIRTQ_AVAIL_F_NO_INTERRUPT  1

#define VIRTIO_BLK_T_IN  0
#define VIRTIO_BLK_T_OUT 1

/* ── CSR helpers ─────────────────────────────────────────────────────────── */
#define READ_CSR(reg)                                                          \
    ({                                                                         \
        unsigned long __tmp;                                                   \
        __asm__ __volatile__("csrr %0, " #reg : "=r"(__tmp));                  \
        __tmp;                                                                 \
    })

#define WRITE_CSR(reg, value)                                                  \
    do {                                                                       \
        uint32_t __tmp = (value);                                              \
        __asm__ __volatile__("csrw " #reg ", %0" :: "r"(__tmp));               \
    } while (0)

/* ── Structs ─────────────────────────────────────────────────────────────── */

/* IPC message passed through shared memory (kernel-mapped) */
struct ipc_msg {
    uint8_t  type;                   /* IPC_* constant above                */
    uint8_t  status;                 /* IPC_STATUS_* on reply               */
    uint16_t payload_len;
    uint8_t  payload[IPC_VALUE_MAX]; /* request params / response data      */
} __attribute__((packed));

/* Process control block */
struct process {
    int      pid;
    int      state;
    uint8_t  capabilities;          /* CAP_* bitmask                        */
    vaddr_t  sp;
    uint32_t *page_table;
    uint8_t  stack[8192];
    /* IPC rendezvous: pointer to shared IPC buffer (kernel-mapped) */
    struct ipc_msg *ipc_buf;
};

/* SBI return value */
struct sbiret {
    long error;
    long value;
};

/* Trap frame – all caller/callee-saved registers */
struct trap_frame {
    uint32_t ra, gp, tp;
    uint32_t t0, t1, t2, t3, t4, t5, t6;
    uint32_t a0, a1, a2, a3, a4, a5, a6, a7;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
    uint32_t sp;
} __attribute__((packed));

/* VirtIO descriptor table */
struct virtq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed));

struct virtq_avail {
    uint16_t flags;
    uint16_t index;
    uint16_t ring[VIRTQ_ENTRY_NUM];
} __attribute__((packed));

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
} __attribute__((packed));

struct virtq_used {
    uint16_t flags;
    uint16_t index;
    struct virtq_used_elem ring[VIRTQ_ENTRY_NUM];
} __attribute__((packed));

struct virtio_virtq {
    struct virtq_desc  descs[VIRTQ_ENTRY_NUM];
    struct virtq_avail avail;
    struct virtq_used  used __attribute__((aligned(PAGE_SIZE)));
    int                queue_index;
    volatile uint16_t *used_index;
    uint16_t           last_used_index;
} __attribute__((packed));

struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
    uint8_t  data[512];
    uint8_t  status;
} __attribute__((packed));

/* TAR filesystem (ustar) */
struct tar_header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char type;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
    char data[];
} __attribute__((packed));

struct file {
    bool  in_use;
    char  name[100];
    char  data[FILE_DATA_MAX];
    size_t size;
};
