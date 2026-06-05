/*
 * kernel.h — Protheus OS kernel definitions.
 *
 * Declares every struct, constant, and prototype shared between kernel.c
 * and the userspace service binaries.  Services include this header
 * directly so the IPC wire format is kept in one place.
 *
 * Architecture: RISC-V rv32ima, SV32 two-level paging, OpenSBI, QEMU virt.
 *
 * Author:  m26steph@uwaterloo.ca
 */
#pragma once
#include "common.h"

/* ══════════════════════════════════════════════════════════════════════════
 * SCHEDULER
 * ══════════════════════════════════════════════════════════════════════════ */

#define PROCS_MAX     16    /* maximum simultaneous processes (kernel + services) */

/* Process state values stored in process.state */
#define PROC_UNUSED   0     /* slot is free and may be allocated                 */
#define PROC_RUNNABLE 1     /* process is ready to run (or currently running)    */
#define PROC_BLOCKED  2     /* process is blocked waiting for an IPC reply       */
#define PROC_EXITED   3     /* process called SYS_EXIT; slot may be reclaimed    */

/* ══════════════════════════════════════════════════════════════════════════
 * CAPABILITY BITMASK
 *
 * Every process has an 8-bit capability field set at spawn time by the
 * kernel.  A process may only issue IPC calls to services it has a
 * capability for.  The kernel enforces this at every do_ipc_call().
 *
 * This prevents a compromised network_service (which sees raw untrusted
 * network bytes) from ever reaching crypto_service's key material, because
 * network_service holds CAP_LOG|CAP_TIMER only — no CAP_CRYPTO bit.
 * ══════════════════════════════════════════════════════════════════════════ */
#define CAP_NONE    0x00          /* no capabilities                             */
#define CAP_CRYPTO  (1 << 0)     /* may call IPC_CRYPTO_*                       */
#define CAP_KVSTORE (1 << 1)     /* may call IPC_KV_*                           */
#define CAP_NETWORK (1 << 2)     /* may call IPC_NET_*                          */
#define CAP_TIMER   (1 << 3)     /* may use timer / yield-loop sleep            */
#define CAP_LOG     (1 << 4)     /* may call SYS_PUTCHAR (printf)               */
#define CAP_ALL     0xFF          /* monerod: orchestrator needs everything      */

/* ══════════════════════════════════════════════════════════════════════════
 * IPC MESSAGE TYPES  (kernel-mediated, capability-gated)
 * ══════════════════════════════════════════════════════════════════════════ */

/* Crypto service requests */
#define IPC_CRYPTO_HASH     0x01  /* SHA-256 hash of payload bytes               */
#define IPC_CRYPTO_SIGN     0x02  /* Ed25519 sign (returns 64-byte signature)     */
#define IPC_CRYPTO_VERIFY   0x03  /* Ed25519 verify (pubkey||sig||msg in payload) */

/* Key-value store requests */
#define IPC_KV_PUT          0x10  /* store key→value pair                        */
#define IPC_KV_GET          0x11  /* retrieve value by key                       */

/* Network service requests */
#define IPC_NET_BROADCAST   0x20  /* relay a signed TX to all peers              */
#define IPC_NET_FETCH_BLOCK 0x21  /* pull the next block from the network        */

/* Utility */
#define IPC_HEARTBEAT       0xFF  /* monerod watchdog ping → network_service ACK */

/* IPC status codes written into ipc_msg.status by the callee */
#define IPC_STATUS_OK       0     /* request completed successfully              */
#define IPC_STATUS_DENIED   1     /* caller lacks the required capability        */
#define IPC_STATUS_ERROR    2     /* callee encountered a processing error       */
#define IPC_STATUS_NOTFOUND 3     /* kv_store: key does not exist                */

/* ══════════════════════════════════════════════════════════════════════════
 * IPC BUFFER SIZES
 * ══════════════════════════════════════════════════════════════════════════ */
#define IPC_KEY_MAX   64    /* maximum key length for kv_store calls             */
#define IPC_VALUE_MAX 512   /* maximum value / payload size in bytes             */
#define IPC_HASH_LEN  32    /* SHA-256 output: 256 bits = 32 bytes               */
#define IPC_SIG_LEN   64    /* Ed25519 signature: 512 bits = 64 bytes            */

/* ══════════════════════════════════════════════════════════════════════════
 * IPC MESSAGE STRUCT
 *
 * Shared between caller and callee via a kernel-mapped page.
 * The kernel fills type+payload before making the callee RUNNABLE.
 * The callee fills status+payload_len+payload, then sets type=0 to signal
 * completion.  The caller resumes and reads the reply from the same buffer.
 * ══════════════════════════════════════════════════════════════════════════ */
struct ipc_msg {
    uint8_t  type;                   /* IPC_* constant written by caller          */
    uint8_t  status;                 /* IPC_STATUS_* written by callee            */
    uint16_t payload_len;            /* byte count of valid data in payload[]     */
    uint8_t  payload[IPC_VALUE_MAX]; /* request data (caller) / reply data (callee) */
};

/* ══════════════════════════════════════════════════════════════════════════
 * RISC-V / SV32 CONSTANTS
 * ══════════════════════════════════════════════════════════════════════════ */

/* satp CSR: mode field.  SV32 = bit 31 set, plus PPN in bits 21:0. */
#define SATP_SV32    (1u << 31)      /* enable SV32 two-level paging             */

/* sstatus CSR bit fields */
#define SSTATUS_SPIE (1 << 5)        /* S Previous Interrupt Enable (restore ie on sret) */
#define SSTATUS_SUM  (1 << 18)       /* Supervisor User Memory access (S can read U pages) */

/* scause values for the trap types we handle */
#define SCAUSE_ECALL 8               /* environment call from U-mode             */

/* SV32 page-table entry (PTE) flag bits */
#define PAGE_V (1 << 0)              /* Valid: PTE is active                     */
#define PAGE_R (1 << 1)              /* Read permission                          */
#define PAGE_W (1 << 2)              /* Write permission                         */
#define PAGE_X (1 << 3)              /* Execute permission                       */
#define PAGE_U (1 << 4)              /* User-mode accessible                     */

/* Virtual address where all user processes are loaded */
#define USER_BASE 0x1000000          /* 16 MiB mark — safely above kernel range  */

/* ══════════════════════════════════════════════════════════════════════════
 * FILESYSTEM CONSTANTS (TAR-based, stored on VirtIO-blk)
 * ══════════════════════════════════════════════════════════════════════════ */
#define FILES_MAX      8             /* maximum number of files on disk           */
#define FILE_DATA_MAX  4096          /* maximum size of a single file in bytes    */
#define SECTOR_SIZE    512           /* VirtIO-blk sector size                   */
/* Total disk image size: one sector-aligned slot per file                  */
#define DISK_MAX_SIZE  align_up(sizeof(struct file) * FILES_MAX, SECTOR_SIZE)

/* ══════════════════════════════════════════════════════════════════════════
 * VIRTIO BLOCK DEVICE CONSTANTS  (QEMU virt machine memory map)
 * ══════════════════════════════════════════════════════════════════════════ */
#define VIRTQ_ENTRY_NUM          16        /* number of descriptors per ring           */
#define VIRTIO_DEVICE_BLK        2         /* VirtIO device ID for block device        */
#define VIRTIO_BLK_PADDR         0x10001000/* MMIO base address in QEMU virt           */

/* VirtIO MMIO register offsets (legacy interface, version 1) */
#define VIRTIO_REG_MAGIC         0x000     /* should read 0x74726976 ("virt")          */
#define VIRTIO_REG_VERSION       0x004     /* should read 1 (legacy)                   */
#define VIRTIO_REG_DEVICE_ID     0x008     /* device type: 2 = block                   */
#define VIRTIO_REG_VENDOR_ID     0x00c     /* vendor, unused                           */
#define VIRTIO_REG_DEVICE_FEATURES 0x010   /* feature bits from device                 */
#define VIRTIO_REG_DRIVER_FEATURES 0x020   /* feature bits from driver (us)            */
#define VIRTIO_REG_PAGE_SIZE     0x028     /* page size driver uses                    */
#define VIRTIO_REG_QUEUE_SEL     0x030     /* select virtqueue index                   */
#define VIRTIO_REG_QUEUE_NUM_MAX 0x034     /* max queue size                           */
#define VIRTIO_REG_QUEUE_NUM     0x038     /* set  queue size                          */
#define VIRTIO_REG_QUEUE_PFN     0x040     /* physical page frame of queue struct      */
#define VIRTIO_REG_QUEUE_NOTIFY  0x050     /* write queue index to kick device         */
#define VIRTIO_REG_INTERRUPT_STATUS 0x060  /* interrupt cause bitmask                  */
#define VIRTIO_REG_INTERRUPT_ACK    0x064  /* write to clear interrupt                 */
#define VIRTIO_REG_DEVICE_STATUS    0x070  /* driver state machine                     */
#define VIRTIO_REG_DEVICE_CONFIG    0x100  /* device-specific config (block: capacity) */

/* VirtIO device status bits (written to VIRTIO_REG_DEVICE_STATUS) */
#define VIRTIO_STATUS_ACK        1         /* OS noticed the device                    */
#define VIRTIO_STATUS_DRIVER     2         /* OS knows how to drive it                 */
#define VIRTIO_STATUS_DRIVER_OK  4         /* driver is set up and ready               */
#define VIRTIO_STATUS_FAILED     128       /* something went wrong                     */

/* VirtIO block request types */
#define VIRTIO_BLK_T_IN          0         /* read  sector(s) from device              */
#define VIRTIO_BLK_T_OUT         1         /* write sector(s) to   device              */

/* VirtQ descriptor flags */
#define VIRTQ_DESC_F_NEXT        1         /* this descriptor chains to .next          */
#define VIRTQ_DESC_F_WRITE       2         /* memory is written by device (not driver) */

/* ══════════════════════════════════════════════════════════════════════════
 * STRUCT DEFINITIONS
 * ══════════════════════════════════════════════════════════════════════════ */

/* SBI return value pair (error code + value) */
struct sbiret {
    long error;   /* SBI error code: 0 = success                              */
    long value;   /* SBI return value (e.g. character for sbi_console_getchar)*/
};

/* VirtIO queue descriptor: describes one buffer segment */
struct virtq_desc {
    uint64_t addr;    /* physical address of the buffer                        */
    uint32_t len;     /* length in bytes                                       */
    uint16_t flags;   /* VIRTQ_DESC_F_* bitmask                               */
    uint16_t next;    /* index of next descriptor if VIRTQ_DESC_F_NEXT set     */
};

/* VirtIO available ring: driver→device notification of new descriptors */
struct virtq_avail {
    uint16_t flags;                       /* 1 = no interrupt needed           */
    uint16_t index;                       /* next slot driver will write       */
    uint16_t ring[VIRTQ_ENTRY_NUM];       /* descriptor head indices           */
};

/* VirtIO used ring entry: device→driver notification of completed work */
struct virtq_used_elem {
    uint32_t id;     /* head descriptor index of the chain                    */
    uint32_t len;    /* bytes written into the buffer (reads only)            */
};

/* VirtIO used ring: device→driver completion notifications */
struct virtq_used {
    uint16_t flags;                           /* 1 = no interrupt needed       */
    uint16_t index;                           /* next slot device will write   */
    struct virtq_used_elem ring[VIRTQ_ENTRY_NUM]; /* completed descriptor chains */
};

/* Full VirtIO virtqueue: descriptors + available ring + used ring */
struct virtio_virtq {
    struct virtq_desc  descs[VIRTQ_ENTRY_NUM]; /* buffer descriptor table       */
    struct virtq_avail avail;                  /* driver→device available ring  */
    uint8_t            _pad[PAGE_SIZE          /* align used ring to page size  */
        - sizeof(struct virtq_desc) * VIRTQ_ENTRY_NUM
        - sizeof(struct virtq_avail)];
    struct virtq_used  used;                   /* device→driver used ring       */
    uint16_t           queue_index;            /* which virtqueue this is (0=blk) */
    uint16_t           last_used_index;        /* driver's last-seen used.index */
    volatile uint16_t *used_index;             /* pointer into used.index       */
};

/* VirtIO block request header + data + status (sent as three descriptor chain) */
struct virtio_blk_req {
    uint32_t type;              /* VIRTIO_BLK_T_IN or VIRTIO_BLK_T_OUT         */
    uint32_t reserved;          /* must be zero                                 */
    uint64_t sector;            /* 512-byte sector number to access             */
    uint8_t  data[SECTOR_SIZE]; /* data buffer: device reads from here on OUT, writes on IN */
    uint8_t  status;            /* device writes 0=OK, 1=IOERR, 2=UNSUP here  */
};

/* TAR file header (ustar format) */
struct tar_header {
    char name[100];    /* NUL-terminated file name                              */
    char mode[8];      /* octal permissions string                              */
    char uid[8];       /* user ID (unused)                                      */
    char gid[8];       /* group ID (unused)                                     */
    char size[12];     /* file size in octal ASCII                              */
    char mtime[12];    /* modification time (unused)                            */
    char checksum[8];  /* header checksum in octal ASCII                        */
    char type;         /* '0' = regular file                                    */
    char linkname[100];/* link target (unused)                                  */
    char magic[6];     /* "ustar" for POSIX tar                                 */
    char version[2];   /* "00"                                                  */
    char uname[32];    /* user name (unused)                                    */
    char gname[32];    /* group name (unused)                                   */
    char devmajor[8];  /* device major (unused)                                 */
    char devminor[8];  /* device minor (unused)                                 */
    char prefix[155];  /* path prefix (unused)                                  */
    char _pad[12];     /* padding to 512-byte sector boundary                   */
    uint8_t data[];    /* file content follows immediately after header          */
};

/* In-memory file slot (TAR content cached after fs_init) */
struct file {
    bool    in_use;                /* slot is occupied                          */
    char    name[100];             /* file name                                 */
    int     size;                  /* byte count of valid data                  */
    uint8_t data[FILE_DATA_MAX];   /* file content                              */
};

/* Trap frame saved by kernel_entry() on the kernel stack during a trap.
 * The layout MUST match the sw/lw sequence in the naked kernel_entry asm. */
struct trap_frame {
    uint32_t ra;    /* x1  return address                                       */
    uint32_t gp;    /* x3  global pointer                                       */
    uint32_t tp;    /* x4  thread pointer                                       */
    uint32_t t0;    /* x5  temporary                                            */
    uint32_t t1;    /* x6  temporary                                            */
    uint32_t t2;    /* x7  temporary                                            */
    uint32_t t3;    /* x28 temporary                                            */
    uint32_t t4;    /* x29 temporary                                            */
    uint32_t t5;    /* x30 temporary                                            */
    uint32_t t6;    /* x31 temporary                                            */
    uint32_t a0;    /* x10 argument / return value — syscall retval goes here   */
    uint32_t a1;    /* x11 argument                                             */
    uint32_t a2;    /* x12 argument                                             */
    uint32_t a3;    /* x13 argument — syscall number                            */
    uint32_t a4;    /* x14 argument — used by SYS_KV_PUT for vlen              */
    uint32_t a5;    /* x15 argument                                             */
    uint32_t a6;    /* x16 argument                                             */
    uint32_t a7;    /* x17 argument                                             */
    uint32_t s0;    /* x8  saved register / frame pointer                       */
    uint32_t s1;    /* x9  saved register                                       */
    uint32_t s2;    /* x18 saved register                                       */
    uint32_t s3;    /* x19 saved register                                       */
    uint32_t s4;    /* x20 saved register                                       */
    uint32_t s5;    /* x21 saved register                                       */
    uint32_t s6;    /* x22 saved register                                       */
    uint32_t s7;    /* x23 saved register                                       */
    uint32_t s8;    /* x24 saved register                                       */
    uint32_t s9;    /* x25 saved register                                       */
    uint32_t s10;   /* x26 saved register                                       */
    uint32_t s11;   /* x27 saved register                                       */
    uint32_t sp;    /* x2  stack pointer — saved last, restored first           */
};

/* Per-process kernel control block */
struct process {
    int              pid;                      /* process ID: 0=idle, 1..N=services  */
    int              state;                    /* PROC_UNUSED / RUNNABLE / BLOCKED / EXITED */
    uint32_t         sp;                       /* saved stack pointer (on context switch) */
    uint8_t          capabilities;             /* CAP_* bitmask checked at IPC time   */
    uint32_t        *page_table;               /* pointer to top-level SV32 page table */
    struct ipc_msg  *ipc_buf;                  /* shared IPC page (mapped R/W user)   */
    uint8_t          stack[8192];              /* kernel stack for this process        */
};

/* ══════════════════════════════════════════════════════════════════════════
 * KERNEL FUNCTION PROTOTYPES
 * ══════════════════════════════════════════════════════════════════════════ */
void             putchar       (char ch);
long             getchar       (void);
void             virtio_blk_init(void);
void             read_write_disk(void *buf, unsigned sector, int is_write);
void             fs_init       (void);
void             fs_flush      (void);
struct file     *fs_lookup     (const char *name);
void             yield         (void);
struct process  *create_process(const void *image, size_t image_size, uint8_t caps);
void             handle_trap   (struct trap_frame *f);
void             kernel_entry  (void);   /* naked trap entry  */
void             user_entry    (void);   /* naked sret to user */
void             switch_context(uint32_t *prev_sp, uint32_t *next_sp); /* naked ctx switch */
void             kernel_main   (void);
void             boot          (void);   /* naked reset entry  */
