/*
 * Protheus OS — Kernel Definitions
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * Architecture: RISC-V rv32ima, SV32 paging, OpenSBI, VirtIO-blk
 *
 * Isolation model (capability bitmask enforced at every IPC syscall):
 *   crypto_service  — CAP_LOG only           (key material never leaves)
 *   kv_store        — CAP_LOG only            (no network route)
 *   network_service — CAP_LOG | CAP_TIMER     (untrusted external data)
 *   monerod         — CAP_ALL except raw HW   (sole orchestrator)
 *
 * CHANGES vs original:
 *   - Added PROC_WAITING state for event-driven IPC sleep (replaces busy-wait)
 *   - Added ipc_notify_pid to process struct (tracks who to wake on IPC reply)
 *   - Added IPC_NOTIFY syscall mechanism
 *   - Added TRNG CSR address for hardware entropy
 *   - Every field and constant annotated
 */
#pragma once
#include "common.h"

/* ── Scheduler states ──────────────────────────────────────────────────── */
#define PROCS_MAX      16       /* maximum concurrent processes             */
#define PROC_UNUSED    0        /* slot is free — can be allocated          */
#define PROC_RUNNABLE  1        /* on the run queue — eligible for CPU      */
#define PROC_BLOCKED   2        /* blocked waiting for IPC reply            */
#define PROC_WAITING   3        /* blocked in SYS_IPC_WAIT (server side)    */
#define PROC_EXITED    4        /* process called SYS_EXIT — slot reclaimable */

/* ── Capabilities ──────────────────────────────────────────────────────── */
/* Each bit grants permission to invoke the corresponding IPC target.
   The kernel checks (caller->capabilities & req_cap) before every IPC.   */
#define CAP_NONE    0x00          /* no capabilities                        */
#define CAP_CRYPTO  (1 << 0)     /* may call crypto_service (hash/sign)    */
#define CAP_KVSTORE (1 << 1)     /* may call kv_store (get/put)            */
#define CAP_NETWORK (1 << 2)     /* may call network_service (tx/fetch)    */
#define CAP_TIMER   (1 << 3)     /* may use timer/sleep syscalls           */
#define CAP_LOG     (1 << 4)     /* may emit console output via SYS_PUTCHAR */
#define CAP_ALL     0xFF          /* unrestricted (monerod orchestrator)    */

/* ── IPC message types ─────────────────────────────────────────────────── */
/* Written into ipc_buf->type by the caller; cleared to 0 by the server
   after the reply is written so the caller knows the response is ready.   */
#define IPC_CRYPTO_HASH     0x01  /* compute SHA-256 of payload            */
#define IPC_CRYPTO_SIGN     0x02  /* Ed25519-sign payload with service key */
#define IPC_CRYPTO_VERIFY   0x03  /* verify Ed25519 sig (pubkey||sig||msg) */
#define IPC_KV_PUT          0x10  /* store key→value in the KV table       */
#define IPC_KV_GET          0x11  /* retrieve value by key                 */
#define IPC_NET_BROADCAST   0x20  /* broadcast raw TX bytes to peers       */
#define IPC_NET_FETCH_BLOCK 0x21  /* pull next block from best peer        */
#define IPC_HEARTBEAT       0xFF  /* liveness check — server replies OK    */

/* ── IPC status codes ──────────────────────────────────────────────────── */
#define IPC_STATUS_OK       0     /* operation completed successfully       */
#define IPC_STATUS_DENIED   1     /* caller lacks the required capability   */
#define IPC_STATUS_ERROR    2     /* internal error in the service          */
#define IPC_STATUS_NOTFOUND 3     /* KV key does not exist                  */

/* ── IPC buffer size limits ────────────────────────────────────────────── */
#define IPC_KEY_MAX   64          /* maximum key length for kv_store        */
#define IPC_VALUE_MAX 512         /* maximum payload / value size           */
#define IPC_HASH_LEN  32          /* SHA-256 output = 32 bytes              */
#define IPC_SIG_LEN   64          /* Ed25519 signature = 64 bytes           */

/* ── RISC-V / SV32 constants ───────────────────────────────────────────── */
#define SATP_SV32    (1u << 31)   /* satp.MODE = Sv32 (bit 31 set)          */
#define SSTATUS_SPIE (1 << 5)     /* sstatus.SPIE — enable user interrupts  */
#define SSTATUS_SUM  (1 << 18)    /* sstatus.SUM  — supervisor can access U pages */
#define SCAUSE_ECALL 8            /* scause value for U-mode ecall          */

/* Page-table entry flag bits (SV32 PTE format) */
#define PAGE_V (1 << 0)   /* Valid — PTE is active                         */
#define PAGE_R (1 << 1)   /* Read permission                               */
#define PAGE_W (1 << 2)   /* Write permission                              */
#define PAGE_X (1 << 3)   /* Execute permission                            */
#define PAGE_U (1 << 4)   /* User-mode accessible                          */

/* Virtual address where every user process begins (arbitrary, below kernel) */
#define USER_BASE 0x1000000

/* ── RISC-V TRNG CSR (seed) ────────────────────────────────────────────── */
/* RISC-V Zkt/Zkr extension: reading CSR 0x015 (seed) returns 32 bits of
   entropy.  ES16 field (bits [31:30] == 01) indicates valid entropy.
   On hardware that lacks Zkr we fall back to a cycle-counter mix.         */
#define CSR_SEED     0x015        /* RISC-V seed CSR address                */
#define SEED_ES16    (1u << 30)   /* entropy-status field bit 30 = ES16 valid */

/* ── Filesystem ────────────────────────────────────────────────────────── */
#define FILES_MAX     8           /* number of files supported in TAR image */
#define FILE_DATA_MAX 4096        /* maximum bytes per file                 */
#define SECTOR_SIZE   512         /* VirtIO block device sector size        */
/* Total disk usage = FILES_MAX file structs, rounded to sector boundary   */
#define DISK_MAX_SIZE align_up(sizeof(struct file) * FILES_MAX, SECTOR_SIZE)

/* ── VirtIO block device ───────────────────────────────────────────────── */
#define VIRTQ_ENTRY_NUM          16           /* descriptor ring size       */
#define VIRTIO_DEVICE_BLK        2            /* VirtIO device ID for block */
#define VIRTIO_BLK_PADDR         0x10001000   /* MMIO base (QEMU virt)     */

/* VirtIO MMIO register offsets from VIRTIO_BLK_PADDR */
#define VIRTIO_REG_MAGIC         0x00   /* must read 0x74726976 ("virt")   */
#define VIRTIO_REG_VERSION       0x04   /* legacy = 1, modern = 2          */
#define VIRTIO_REG_DEVICE_ID     0x08   /* 2 = block device                */
#define VIRTIO_REG_PAGE_SIZE     0x28   /* write PAGE_SIZE here            */
#define VIRTIO_REG_QUEUE_SEL     0x30   /* select which queue to configure */
#define VIRTIO_REG_QUEUE_NUM_MAX 0x34   /* read: max descriptor count      */
#define VIRTIO_REG_QUEUE_NUM     0x38   /* write: actual descriptor count  */
#define VIRTIO_REG_QUEUE_PFN     0x40   /* write: page-frame of virtq      */
#define VIRTIO_REG_QUEUE_NOTIFY  0x50   /* write queue index to kick device */
#define VIRTIO_REG_DEVICE_STATUS 0x70   /* driver/device handshake flags   */
#define VIRTIO_REG_DEVICE_CONFIG 0x100  /* device-specific config space    */

/* VirtIO device status bits (written in order during initialisation) */
#define VIRTIO_STATUS_ACK        1   /* OS has noticed the device          */
#define VIRTIO_STATUS_DRIVER     2   /* OS knows how to drive the device   */
#define VIRTIO_STATUS_DRIVER_OK  4   /* Driver setup is complete           */

/* VirtIO descriptor flags */
#define VIRTQ_DESC_F_NEXT        1   /* descriptor chain continues         */
#define VIRTQ_DESC_F_WRITE       2   /* buffer is device-writable (read)   */

/* VirtIO block request types */
#define VIRTIO_BLK_T_IN  0    /* read from device into RAM               */
#define VIRTIO_BLK_T_OUT 1    /* write from RAM to device                */

/* ── CSR macros ────────────────────────────────────────────────────────── */
/*
 * READ_CSR — read a control/status register into an unsigned long.
 * The "=r" constraint means the compiler picks any GPR for the result.
 */
#define READ_CSR(reg)                                              \
    ({                                                             \
        unsigned long __v;                                         \
        __asm__ __volatile__("csrr %0, " #reg : "=r"(__v));       \
        __v;                                                       \
    })

/*
 * WRITE_CSR — write a 32-bit value to a control/status register.
 * The "r" constraint means the value must be in a GPR first.
 */
#define WRITE_CSR(reg, val)                                        \
    do {                                                           \
        uint32_t __v = (val);                                      \
        __asm__ __volatile__("csrw " #reg ", %0" :: "r"(__v));    \
    } while (0)

/* ── Structs ───────────────────────────────────────────────────────────── */

/*
 * ipc_msg — rendezvous buffer between caller and server.
 * One page is allocated per process; the kernel maps it user-accessible.
 * The kernel writes the request; the server writes the reply; the kernel
 * copies the reply back to the caller's registers.
 *
 * Packed to avoid padding — the payload is always at a fixed byte offset.
 */
struct ipc_msg {
    uint8_t  type;          /* IPC_* constant — 0 means "no pending request" */
    uint8_t  status;        /* IPC_STATUS_* filled by server after handling   */
    uint16_t payload_len;   /* number of valid bytes in payload[]             */
    uint8_t  payload[IPC_VALUE_MAX];  /* request data (in) / reply data (out) */
} __attribute__((packed));

/*
 * process — process control block (PCB).
 * Embedded stack avoids a separate allocation; ipc_buf is a kernel-allocated
 * shared page that is also mapped into the process's address space.
 */
struct process {
    int             pid;           /* unique process ID (1-based)             */
    int             state;         /* PROC_* scheduling state                 */
    uint8_t         capabilities;  /* CAP_* bitmask — enforced at IPC         */
    vaddr_t         sp;            /* saved stack pointer (used by ctx switch) */
    uint32_t       *page_table;    /* root SV32 page-table (physical address)  */
    uint8_t         stack[8192];   /* kernel stack (8 KiB)                    */
    struct ipc_msg *ipc_buf;       /* kernel-allocated IPC rendezvous page    */
    int             ipc_notify_pid;/* pid to wake after replying (-1 = none)  */
} __attribute__((aligned(16)));   /* align PCB so sp arithmetic is safe      */

/*
 * sbiret — return value from an SBI ecall.
 * error < 0 means failure; value carries the result on success.
 */
struct sbiret {
    long error;   /* SBI error code (0 = success, negative = failure)        */
    long value;   /* return value when error == 0                            */
};

/*
 * trap_frame — snapshot of all user registers saved on the kernel stack
 * at trap entry.  handle_trap() receives a pointer to this frame.
 * packed so the assembly offsets (4*N) match exactly.
 */
struct trap_frame {
    uint32_t ra, gp, tp;                              /* return addr, globals */
    uint32_t t0, t1, t2, t3, t4, t5, t6;             /* temporaries          */
    uint32_t a0, a1, a2, a3, a4, a5, a6, a7;         /* arguments / returns  */
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7,
             s8, s9, s10, s11;                        /* callee-saved         */
    uint32_t sp;                                      /* user stack pointer   */
} __attribute__((packed));

/* ── VirtIO ring structures ────────────────────────────────────────────── */

/* virtq_desc — one entry in the descriptor table */
struct virtq_desc {
    uint64_t addr;    /* guest-physical address of buffer                   */
    uint32_t len;     /* length of buffer in bytes                          */
    uint16_t flags;   /* VIRTQ_DESC_F_* flags                               */
    uint16_t next;    /* index of next descriptor in chain (if F_NEXT set)  */
} __attribute__((packed));

/* virtq_avail — available ring: driver posts buffers here for device       */
struct virtq_avail {
    uint16_t flags;                      /* 1 = suppress used-ring interrupt */
    uint16_t index;                      /* next slot driver will write to   */
    uint16_t ring[VIRTQ_ENTRY_NUM];      /* descriptor indices               */
} __attribute__((packed));

/* virtq_used_elem — one entry in the used ring */
struct virtq_used_elem {
    uint32_t id;    /* descriptor chain head index                          */
    uint32_t len;   /* total bytes written by device                        */
} __attribute__((packed));

/* virtq_used — used ring: device writes completed buffers here             */
struct virtq_used {
    uint16_t flags;                          /* 1 = suppress avail interrupt */
    uint16_t index;                          /* next slot device will write  */
    struct virtq_used_elem ring[VIRTQ_ENTRY_NUM]; /* completed entries       */
} __attribute__((packed));

/*
 * virtio_virtq — complete virtqueue (desc + avail + used).
 * The used ring is page-aligned as required by the VirtIO spec.
 */
struct virtio_virtq {
    struct virtq_desc  descs[VIRTQ_ENTRY_NUM];  /* descriptor table          */
    struct virtq_avail avail;                   /* available ring            */
    /* pad to page boundary before used ring */
    struct virtq_used  used __attribute__((aligned(PAGE_SIZE)));
    int                queue_index;             /* index of this queue (0)   */
    volatile uint16_t *used_index;              /* pointer to used->index    */
    uint16_t           last_used_index;         /* last index we consumed    */
} __attribute__((packed));

/* virtio_blk_req — DMA descriptor for one block I/O operation             */
struct virtio_blk_req {
    uint32_t type;       /* VIRTIO_BLK_T_IN or VIRTIO_BLK_T_OUT            */
    uint32_t reserved;   /* must be zero                                    */
    uint64_t sector;     /* 512-byte sector number on the virtual disk      */
    uint8_t  data[512];  /* one sector of data                              */
    uint8_t  status;     /* device writes 0 = OK, 1 = IOERR, 2 = UNSUPP   */
} __attribute__((packed));

/* ustar TAR header — 512 bytes exactly */
struct tar_header {
    char name[100];       /* file name (NUL-padded)                         */
    char mode[8];         /* octal permissions                              */
    char uid[8];          /* owner UID                                      */
    char gid[8];          /* owner GID                                      */
    char size[12];        /* octal file size                                */
    char mtime[12];       /* octal modification time                        */
    char checksum[8];     /* header checksum                                */
    char type;            /* '0' = regular file                             */
    char linkname[100];   /* hard-link target (unused)                      */
    char magic[6];        /* "ustar" NUL-terminated                         */
    char version[2];      /* "00"                                           */
    char uname[32];       /* owner user name                                */
    char gname[32];       /* owner group name                               */
    char devmajor[8];     /* device major number                            */
    char devminor[8];     /* device minor number                            */
    char prefix[155];     /* path prefix for long names                     */
    char padding[12];     /* round to 512 bytes                             */
    char data[];          /* file data begins immediately after header      */
} __attribute__((packed));

/* file — one in-memory file from the TAR disk image                       */
struct file {
    bool   in_use;            /* true if this slot holds a valid file       */
    char   name[100];         /* file name (NUL-terminated)                 */
    char   data[FILE_DATA_MAX]; /* file contents                            */
    size_t size;              /* valid bytes in data[]                      */
};

/* ── Kernel API ────────────────────────────────────────────────────────── */
/* These are implemented in kernel.c and used internally or via syscalls. */
void yield(void);                         /* cooperative scheduler yield    */
void handle_trap(struct trap_frame *f);   /* trap/interrupt entry point     */
