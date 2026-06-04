/*
 * Protheus OS — Kernel
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * RISC-V rv32ima | SV32 paging | OpenSBI | VirtIO-blk
 *
 * Boot order:
 *   boot() → kernel_main() → virtio_blk_init() → fs_init()
 *            → spawn services (crypto, kv_store, network, monerod)
 *            → yield() into scheduler loop
 *
 * IPC flow (capability-gated, event-driven):
 *   user ecall → handle_trap → handle_syscall → do_ipc_call
 *     → target->state = PROC_RUNNABLE, caller->state = PROC_BLOCKED
 *     → yield() (target runs, writes reply into shared ipc_buf)
 *     → target calls SYS_IPC_NOTIFY → caller->state = PROC_RUNNABLE
 *     → scheduler resumes caller, reads reply
 *
 * Server sleep flow (replaces busy-poll):
 *   server calls SYS_IPC_WAIT → state = PROC_WAITING, yield()
 *   kernel (in do_ipc_call) sets server RUNNABLE before unblocking caller
 *
 * CHANGES vs original:
 *   - PROC_WAITING state + SYS_IPC_WAIT / SYS_IPC_NOTIFY syscalls
 *   - SYS_TRNG: reads RISC-V seed CSR; falls back to cycle-counter mix
 *   - do_ipc_call sets ipc_notify_pid so server knows who to wake
 *   - KV store disk flush plumbed through SYS_WRITEFILE
 *   - Every line of code annotated
 */

#include "kernel.h"
#include "common.h"

/* ── Linker symbols (defined in kernel.ld) ──────────────────────────────── */
extern char __kernel_base[];    /* start of kernel .text section           */
extern char __stack_top[];      /* top of kernel boot stack                */
extern char __bss[];            /* start of BSS segment                    */
extern char __bss_end[];        /* end of BSS segment                      */
extern char __free_ram[];       /* start of free physical RAM              */
extern char __free_ram_end[];   /* end of free physical RAM (128 MiB mark) */
/* Shell binary embedded by objcopy into .shell section */
extern char _binary_shell_bin_start[];
extern char _binary_shell_bin_size[];

/* ── Global kernel state ────────────────────────────────────────────────── */
struct process  procs[PROCS_MAX];   /* process table — all PCBs live here  */
struct process *current_proc;       /* PCB of the currently running process */
struct process *idle_proc;          /* special idle process (pid == 0)      */

/* PIDs of well-known service processes; set during boot, read by do_ipc_call */
static int pid_crypto  = -1;   /* crypto_service PID                       */
static int pid_kv      = -1;   /* kv_store PID                             */
static int pid_network = -1;   /* network_service PID                      */

/* ── Physical memory allocator (bump allocator, zeroed pages) ──────────── */

/*
 * alloc_pages — allocate n contiguous physical pages.
 *
 * Uses a simple bump pointer: 'next' advances by n*PAGE_SIZE each call.
 * Pages are zeroed so callers don't see stale data.
 * Panics if RAM is exhausted — there is no free list.
 */
paddr_t alloc_pages(uint32_t n) {
    static paddr_t next = (paddr_t)__free_ram; /* initialised once at link time */
    paddr_t base = next;          /* record current top as the allocation start */
    next += n * PAGE_SIZE;        /* bump pointer past the n pages just claimed */
    if (next > (paddr_t)__free_ram_end)  /* check we haven't walked past RAM   */
        PANIC("out of memory");
    memset((void *)base, 0, n * PAGE_SIZE);  /* zero-fill: prevent info leaks   */
    return base;                  /* return physical address of first page      */
}

/* ── SV32 page-table management ─────────────────────────────────────────── */

/*
 * map_page — install a single 4-KiB page mapping in a two-level SV32 table.
 *
 * SV32 virtual address layout:
 *   [31:22] VPN[1] — index into root (level-1) page table   (10 bits)
 *   [21:12] VPN[0] — index into leaf (level-0) page table   (10 bits)
 *   [11: 0] page offset                                      (12 bits)
 *
 * Each PTE is 32 bits: [31:10] PPN | [9:0] flags.
 * PPN = physical page number = physical_address / PAGE_SIZE.
 */
void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
    /* Enforce alignment — RISC-V PTEs address whole pages */
    if (!is_aligned(vaddr,  PAGE_SIZE)) PANIC("unaligned vaddr %x",  vaddr);
    if (!is_aligned(paddr,  PAGE_SIZE)) PANIC("unaligned paddr %x",  paddr);

    uint32_t vpn1 = (vaddr >> 22) & 0x3ff;  /* bits [31:22]: root table index */
    if (!(table1[vpn1] & PAGE_V)) {          /* if the level-1 PTE is invalid  */
        uint32_t pt = alloc_pages(1);        /* allocate a new level-0 table   */
        /* Store PPN of new level-0 table in root PTE, mark Valid              */
        table1[vpn1] = ((pt / PAGE_SIZE) << 10) | PAGE_V;
    }

    uint32_t vpn0 = (vaddr >> 12) & 0x3ff;  /* bits [21:12]: leaf table index */
    /* Recover pointer to level-0 table from root PTE's PPN field              */
    uint32_t *table0 = (uint32_t *)((table1[vpn1] >> 10) * PAGE_SIZE);
    /* Write leaf PTE: PPN of target physical page | caller-supplied flags | V */
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

/* ── SBI (Supervisor Binary Interface) ──────────────────────────────────── */

/*
 * sbi_call — invoke an OpenSBI function via the ecall instruction.
 *
 * RISC-V SBI calling convention:
 *   a7 = extension ID (EID)
 *   a6 = function  ID (FID)
 *   a0–a5 = arguments
 *   a0 = error code on return (0 = SBI_SUCCESS)
 *   a1 = return value on return
 *
 * We list all modified registers in the clobber list so the compiler
 * does not assume they are preserved across the ecall.
 */
struct sbiret sbi_call(long a0, long a1, long a2, long a3, long a4,
                       long a5, long fid, long eid) {
    /* Place each argument in its designated register using named constraints */
    register long _a0 __asm__("a0") = a0;
    register long _a1 __asm__("a1") = a1;
    register long _a2 __asm__("a2") = a2;
    register long _a3 __asm__("a3") = a3;
    register long _a4 __asm__("a4") = a4;
    register long _a5 __asm__("a5") = a5;
    register long _a6 __asm__("a6") = fid;  /* function ID in a6             */
    register long _a7 __asm__("a7") = eid;  /* extension ID in a7            */
    __asm__ __volatile__("ecall"
                         : "=r"(_a0), "=r"(_a1)        /* outputs: a0, a1     */
                         : "r"(_a0), "r"(_a1), "r"(_a2), "r"(_a3),
                           "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7)  /* inputs  */
                         : "memory");                   /* memory clobber       */
    return (struct sbiret){ .error = _a0, .value = _a1 };
}

/* ── Console helpers (via SBI legacy console extension) ─────────────────── */

/* putchar — emit one character via SBI console putchar (EID=1, FID=0)     */
void putchar(char ch) { sbi_call(ch, 0, 0, 0, 0, 0, 0, 1); }

/* getchar — read one character; returns -1 if no character available       */
long getchar(void) { return sbi_call(0, 0, 0, 0, 0, 0, 0, 2).error; }

/* ── TRNG: hardware entropy source ──────────────────────────────────────── */

/*
 * trng_read32 — return 32 bits of entropy.
 *
 * Preferred: RISC-V Zkr seed CSR (0x015).
 *   Read seed until ES16 field (bits[31:30] == 01) indicates valid entropy.
 *   Mask off status bits to get raw 16-bit entropy in the lower halfword.
 *   Two reads XOR'd together give 32 bits.
 *
 * Fallback: mix rdtime / rdcycle for platforms without Zkr.
 *   This is NOT cryptographically strong — use only if no Zkr.
 */
static uint32_t trng_read32(void) {
    uint32_t s0, s1;

#ifdef RISCV_ZKR
    /* Poll seed CSR until ES16 == 01 (valid entropy word available) */
    do {
        __asm__ __volatile__("csrr %0, 0x015" : "=r"(s0)); /* read seed CSR  */
    } while ((s0 >> 30) != 1);   /* bits[31:30] must be 01 for valid entropy */

    do {
        __asm__ __volatile__("csrr %0, 0x015" : "=r"(s1));
    } while ((s1 >> 30) != 1);   /* second read for upper 16 bits             */

    /* Combine: lower 16 bits of each read → 32 bits of entropy              */
    return ((s0 & 0xFFFF) << 16) | (s1 & 0xFFFF);
#else
    /* Fallback: XOR rdcycle and rdtime (timing-based, not cryptographic)    */
    uint32_t cyc, tim;
    __asm__ __volatile__("rdcycle  %0" : "=r"(cyc));   /* clock cycles        */
    __asm__ __volatile__("rdtime   %0" : "=r"(tim));   /* real-time clock     */
    /* Mix with prime constants (inspired by xorshift/splitmix)               */
    uint32_t mix = cyc ^ tim ^ 0x9e3779b9u;   /* golden-ratio constant mix   */
    mix ^= mix >> 16;    /* avalanche: fold upper bits into lower             */
    mix *= 0x45d9f3bu;   /* multiply by another prime                        */
    mix ^= mix >> 16;    /* second avalanche pass                             */
    return mix;
#endif
}

/*
 * trng_fill — fill `n` bytes with entropy.
 * Called by the SYS_TRNG syscall and by crypto_service key generation.
 */
static void trng_fill(uint8_t *buf, size_t n) {
    while (n >= 4) {                /* full 32-bit words first               */
        uint32_t w = trng_read32();
        buf[0] = (uint8_t)(w);          /* little-endian byte 0              */
        buf[1] = (uint8_t)(w >> 8);     /* little-endian byte 1              */
        buf[2] = (uint8_t)(w >> 16);    /* little-endian byte 2              */
        buf[3] = (uint8_t)(w >> 24);    /* little-endian byte 3              */
        buf += 4;                       /* advance past the 4 bytes written  */
        n   -= 4;                       /* decrement remaining byte count    */
    }
    if (n > 0) {                    /* handle 1–3 leftover bytes             */
        uint32_t w = trng_read32();
        for (size_t i = 0; i < n; i++)
            buf[i] = (uint8_t)(w >> (8 * i));  /* extract byte i from word  */
    }
}

/* ── VirtIO block device ─────────────────────────────────────────────────── */

static struct virtio_virtq *blk_request_vq;   /* virtqueue for I/O requests  */
static struct virtio_blk_req *blk_req;        /* DMA buffer for one I/O req  */
static paddr_t blk_req_paddr;                 /* physical addr of blk_req    */
static uint64_t blk_capacity;                 /* device capacity in sectors  */

/*
 * virtio_reg_read — read a 32-bit VirtIO MMIO register.
 * `offset` is the byte offset from VIRTIO_BLK_PADDR.
 */
static uint32_t virtio_reg_read(uint32_t offset) {
    return MMIO_READ32(VIRTIO_BLK_PADDR + offset);   /* volatile 32-bit read */
}

/*
 * virtio_reg_write — write a 32-bit value to a VirtIO MMIO register.
 */
static void virtio_reg_write(uint32_t offset, uint32_t val) {
    MMIO_WRITE32(VIRTIO_BLK_PADDR + offset, val);    /* volatile 32-bit write */
}

/*
 * virtio_blk_init — initialise the VirtIO block device.
 *
 * Follows the VirtIO 1.0 legacy device initialisation sequence:
 *   1. Verify magic and device ID.
 *   2. Set ACKNOWLEDGE + DRIVER status bits.
 *   3. Configure queue 0.
 *   4. Set DRIVER_OK to complete handshake.
 *   5. Read device capacity from config space.
 */
void virtio_blk_init(void) {
    /* Step 1: verify this is a VirtIO block device */
    if (virtio_reg_read(VIRTIO_REG_MAGIC) != 0x74726976)   /* "virt" magic  */
        PANIC("virtio: bad magic");
    if (virtio_reg_read(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK)
        PANIC("virtio: not a block device");

    /* Step 2: OS acknowledges device and announces driver */
    virtio_reg_write(VIRTIO_REG_DEVICE_STATUS, 0);  /* reset device           */
    virtio_reg_write(VIRTIO_REG_DEVICE_STATUS,
                     VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    /* Step 3: configure virtqueue 0 */
    virtio_reg_write(VIRTIO_REG_PAGE_SIZE, PAGE_SIZE);  /* tell device our pg size */
    virtio_reg_write(VIRTIO_REG_QUEUE_SEL, 0);          /* select queue index 0    */
    uint32_t qmax = virtio_reg_read(VIRTIO_REG_QUEUE_NUM_MAX);  /* read hw limit   */
    if (qmax < VIRTQ_ENTRY_NUM)
        PANIC("virtio: queue too small (%u < %u)", qmax, VIRTQ_ENTRY_NUM);
    virtio_reg_write(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);  /* set our ring size */

    /* Allocate one page for the virtqueue structure */
    paddr_t vq_paddr = alloc_pages(
        align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    blk_request_vq = (struct virtio_virtq *)vq_paddr;
    blk_request_vq->queue_index  = 0;                    /* this is queue 0       */
    blk_request_vq->used_index   = &blk_request_vq->used.index; /* shortcut ptr */
    blk_request_vq->last_used_index = 0;                 /* nothing consumed yet  */

    /* Tell device where our virtqueue lives (in PAGE_SIZE units) */
    virtio_reg_write(VIRTIO_REG_QUEUE_PFN, vq_paddr / PAGE_SIZE);

    /* Allocate DMA buffer for block requests (must be physically contiguous) */
    blk_req_paddr = alloc_pages(1);
    blk_req = (struct virtio_blk_req *)blk_req_paddr;

    /* Step 4: signal that driver setup is complete */
    virtio_reg_write(VIRTIO_REG_DEVICE_STATUS,
                     VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK);

    /* Step 5: read disk capacity (two 32-bit words = 64-bit sector count)   */
    blk_capacity =
        ((uint64_t)virtio_reg_read(VIRTIO_REG_DEVICE_CONFIG + 4) << 32) |
         (uint64_t)virtio_reg_read(VIRTIO_REG_DEVICE_CONFIG);
    printf("virtio-blk: %llu sectors (%llu MiB)\n",
           blk_capacity, blk_capacity / 2048);
}

/*
 * virtio_blk_rw — perform a single-sector read or write.
 *
 * Uses a three-descriptor chain:
 *   desc[0]: request header (type, reserved, sector) — device reads this
 *   desc[1]: data buffer — device reads (WRITE) or writes (READ)
 *   desc[2]: status byte — device writes the result
 *
 * Polling loop waits for the device to update the used ring.
 */
static void virtio_blk_rw(uint64_t sector, int is_write) {
    /* Fill the block request header */
    blk_req->type     = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    blk_req->reserved = 0;         /* spec requires this to be zero          */
    blk_req->sector   = sector;    /* logical block address                  */

    /* Descriptor 0: request header — device-readable, chain continues */
    blk_request_vq->descs[0].addr  = blk_req_paddr;       /* phys addr of header */
    blk_request_vq->descs[0].len   = sizeof(uint32_t) * 2 + sizeof(uint64_t);
    blk_request_vq->descs[0].flags = VIRTQ_DESC_F_NEXT;   /* chain to desc[1]    */
    blk_request_vq->descs[0].next  = 1;

    /* Descriptor 1: data sector — direction depends on read vs write */
    blk_request_vq->descs[1].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    blk_request_vq->descs[1].len   = SECTOR_SIZE;
    /* WRITE flag set = device writes to this buffer (for reads); cleared for writes */
    blk_request_vq->descs[1].flags = VIRTQ_DESC_F_NEXT |
                                      (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    blk_request_vq->descs[1].next  = 2;

    /* Descriptor 2: status byte — device always writes the result */
    blk_request_vq->descs[2].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    blk_request_vq->descs[2].len   = sizeof(uint8_t);
    blk_request_vq->descs[2].flags = VIRTQ_DESC_F_WRITE;  /* device writes status */
    blk_request_vq->descs[2].next  = 0;                   /* end of chain          */

    /* Post descriptor chain 0 to the available ring */
    blk_request_vq->avail.ring[blk_request_vq->avail.index % VIRTQ_ENTRY_NUM] = 0;
    MEM_FENCE();                          /* ensure descriptor is visible before kick */
    blk_request_vq->avail.index++;        /* bump avail index to signal new entry     */
    MEM_FENCE();                          /* ensure index update is visible           */

    /* Kick the device: notify queue 0 has new work */
    virtio_reg_write(VIRTIO_REG_QUEUE_NOTIFY, 0);

    /* Poll until device updates the used ring (synchronous I/O) */
    while (blk_request_vq->used.index == blk_request_vq->last_used_index)
        ;   /* spin — in a real kernel we would sleep on an interrupt         */
    blk_request_vq->last_used_index++;   /* consume the completion entry     */

    if (blk_req->status != 0)            /* 0 = success, non-zero = error    */
        PANIC("virtio-blk: I/O error sector %llu status=%u",
              sector, (unsigned)blk_req->status);
}

/* ── TAR filesystem ──────────────────────────────────────────────────────── */

static struct file files[FILES_MAX];   /* in-memory file table              */

/*
 * oct2int — parse an octal string (as found in TAR headers) into an integer.
 * `len` includes the possible NUL terminator.
 */
static int oct2int(const char *s, int len) {
    int v = 0;
    while (len-- > 0 && *s >= '0' && *s <= '7')  /* while valid octal digit */
        v = (v << 3) | (*s++ - '0');              /* shift left 3, add digit */
    return v;
}

/*
 * fs_flush — write the in-memory file table back to VirtIO disk.
 *
 * Each file struct is written sector-by-sector.  This is called by
 * SYS_WRITEFILE (and by kv_store when it needs to persist its table).
 */
void fs_flush(void) {
    /* Calculate how many sectors the entire file table spans */
    uint32_t total_bytes = sizeof(files);           /* total size of files[]  */
    uint32_t nsectors    = align_up(total_bytes, SECTOR_SIZE) / SECTOR_SIZE;

    for (uint32_t s = 0; s < nsectors; s++) {
        /* Copy one sector from files[] into the DMA buffer */
        memcpy(blk_req->data,
               (const uint8_t *)files + s * SECTOR_SIZE,  /* source offset    */
               SECTOR_SIZE);                               /* copy full sector */
        virtio_blk_rw(s, /*is_write=*/1);   /* issue VirtIO write for sector s */
    }
}

/*
 * fs_init — read the disk TAR image into the in-memory file table.
 *
 * Iterates through 512-byte ustar headers.  Each header is followed by
 * the file data (rounded up to 512-byte sector boundaries).
 */
void fs_init(void) {
    /* Read the full disk range that can hold FILES_MAX file structs */
    uint32_t nsectors = align_up(DISK_MAX_SIZE, SECTOR_SIZE) / SECTOR_SIZE;
    /* Use a local buffer large enough for all sectors */
    /* NOTE: DISK_MAX_SIZE is bounded by FILES_MAX * FILE_DATA_MAX ≤ 32 KiB */
    static uint8_t disk_buf[FILES_MAX * SECTOR_SIZE * 8];  /* generous buffer */
    for (uint32_t s = 0; s < nsectors; s++) {
        virtio_blk_rw(s, /*is_write=*/0);              /* read sector s       */
        memcpy(disk_buf + s * SECTOR_SIZE, blk_req->data, SECTOR_SIZE);
    }

    /* Walk the TAR archive looking for regular files */
    uint32_t off = 0;   /* byte offset into disk_buf */
    for (int i = 0; i < FILES_MAX; i++) {
        struct tar_header *h = (struct tar_header *)(disk_buf + off);
        if (h->name[0] == '\0') break;   /* two consecutive NUL blocks = end */
        if (strncmp(h->magic, "ustar", 5) != 0)   /* validate ustar magic    */
            PANIC("bad tar magic: \"%s\"", h->magic);

        int sz = oct2int(h->size, sizeof(h->size)); /* parse octal file size  */
        if (sz > FILE_DATA_MAX) sz = FILE_DATA_MAX; /* clamp to buffer limit  */

        struct file *f = &files[i];
        f->in_use = true;                           /* mark slot occupied      */
        strncpy(f->name, h->name, 99);              /* copy file name          */
        f->name[99] = '\0';                         /* guarantee NUL terminator */
        memcpy(f->data, h->data, sz);               /* copy file data          */
        f->size = sz;                               /* record valid byte count  */

        printf("fs: '%s' (%d bytes)\n", f->name, f->size);

        /* Advance past header + data, rounded to next 512-byte boundary     */
        off += align_up(sizeof(struct tar_header) + sz, SECTOR_SIZE);
    }
}

/*
 * fs_lookup — find a file by name; returns NULL if not found.
 */
struct file *fs_lookup(const char *name) {
    for (int i = 0; i < FILES_MAX; i++)
        if (files[i].in_use && strcmp(files[i].name, name) == 0)
            return &files[i];   /* found — return pointer to file struct     */
    return NULL;                /* not found                                 */
}

/* ── Trap entry / exit ───────────────────────────────────────────────────── */

/*
 * kernel_entry — raw trap vector (aligned to 4 bytes as required by RISC-V).
 *
 * On entry, sscratch holds the kernel stack top of the current process.
 * We swap sp ↔ sscratch to switch to the kernel stack, then save all
 * 31 user registers onto that stack.  Finally we call handle_trap(sp)
 * where sp now points to the trap_frame.
 *
 * On return from handle_trap we restore all registers and issue sret to
 * return to user mode (sepc was updated by handle_trap to skip the ecall).
 */
__attribute__((naked)) __attribute__((aligned(4)))
void kernel_entry(void) {
    __asm__ __volatile__(
        /* Swap user sp with sscratch (kernel stack pointer) */
        "csrrw sp, sscratch, sp\n"
        /* Allocate 31 words on the kernel stack for the trap frame */
        "addi  sp, sp, -4*31\n"
        /* Save caller-saved and callee-saved registers at fixed offsets */
        "sw ra,  4* 0(sp)\n" "sw gp,  4* 1(sp)\n" "sw tp,  4* 2(sp)\n"
        "sw t0,  4* 3(sp)\n" "sw t1,  4* 4(sp)\n" "sw t2,  4* 5(sp)\n"
        "sw t3,  4* 6(sp)\n" "sw t4,  4* 7(sp)\n" "sw t5,  4* 8(sp)\n"
        "sw t6,  4* 9(sp)\n"
        "sw a0,  4*10(sp)\n" "sw a1,  4*11(sp)\n" "sw a2,  4*12(sp)\n"
        "sw a3,  4*13(sp)\n" "sw a4,  4*14(sp)\n" "sw a5,  4*15(sp)\n"
        "sw a6,  4*16(sp)\n" "sw a7,  4*17(sp)\n"
        "sw s0,  4*18(sp)\n" "sw s1,  4*19(sp)\n" "sw s2,  4*20(sp)\n"
        "sw s3,  4*21(sp)\n" "sw s4,  4*22(sp)\n" "sw s5,  4*23(sp)\n"
        "sw s6,  4*24(sp)\n" "sw s7,  4*25(sp)\n" "sw s8,  4*26(sp)\n"
        "sw s9,  4*27(sp)\n" "sw s10, 4*28(sp)\n" "sw s11, 4*29(sp)\n"
        /* Recover user sp from sscratch and save it as frame->sp */
        "csrr a0, sscratch\n"
        "sw a0,  4*30(sp)\n"
        /* Reset sscratch to point past the frame (next trap's kernel sp)    */
        "addi a0, sp, 4*31\n"
        "csrw sscratch, a0\n"
        /* Pass trap frame pointer as first argument to handle_trap           */
        "mv a0, sp\n"
        "call handle_trap\n"
        /* Restore all registers from the (possibly modified) trap frame     */
        "lw ra,  4* 0(sp)\n" "lw gp,  4* 1(sp)\n" "lw tp,  4* 2(sp)\n"
        "lw t0,  4* 3(sp)\n" "lw t1,  4* 4(sp)\n" "lw t2,  4* 5(sp)\n"
        "lw t3,  4* 6(sp)\n" "lw t4,  4* 7(sp)\n" "lw t5,  4* 8(sp)\n"
        "lw t6,  4* 9(sp)\n"
        "lw a0,  4*10(sp)\n" "lw a1,  4*11(sp)\n" "lw a2,  4*12(sp)\n"
        "lw a3,  4*13(sp)\n" "lw a4,  4*14(sp)\n" "lw a5,  4*15(sp)\n"
        "lw a6,  4*16(sp)\n" "lw a7,  4*17(sp)\n"
        "lw s0,  4*18(sp)\n" "lw s1,  4*19(sp)\n" "lw s2,  4*20(sp)\n"
        "lw s3,  4*21(sp)\n" "lw s4,  4*22(sp)\n" "lw s5,  4*23(sp)\n"
        "lw s6,  4*24(sp)\n" "lw s7,  4*25(sp)\n" "lw s8,  4*26(sp)\n"
        "lw s9,  4*27(sp)\n" "lw s10, 4*28(sp)\n" "lw s11, 4*29(sp)\n"
        /* Restore user sp from frame slot 30 */
        "lw sp,  4*30(sp)\n"
        /* Return to user mode: restores PC from sepc, mode from sstatus.SPP */
        "sret\n"
    );
}

/*
 * user_entry — transition the newly created process into user mode.
 *
 * sepc   = USER_BASE (start address of user binary)
 * sstatus.SPIE = 1 (re-enable interrupts in user mode)
 * sstatus.SUM  = 1 (allow supervisor to access U-mode pages for IPC copy)
 * sret returns to sepc with mode from sstatus.SPP (which we leave as User).
 */
__attribute__((naked)) void user_entry(void) {
    __asm__ __volatile__(
        "csrw sepc,    %[sepc]\n"   /* set PC for sret to USER_BASE          */
        "csrw sstatus, %[st]\n"     /* set SPIE | SUM flags                  */
        "sret\n"
        :: [sepc] "r"(USER_BASE), [st] "r"(SSTATUS_SPIE | SSTATUS_SUM)
    );
}

/* ── Context switch ──────────────────────────────────────────────────────── */

/*
 * switch_context — save callee-saved registers of `prev`, restore `next`'s.
 *
 * Called with:
 *   a0 = &prev->sp  (where to save the current sp)
 *   a1 = &next->sp  (where to load the new sp from)
 *
 * RISC-V calling convention: s0–s11 and ra are callee-saved.
 * We push them onto the kernel stack, save sp, swap, then restore next's.
 */
__attribute__((naked)) void switch_context(uint32_t *prev_sp, uint32_t *next_sp) {
    __asm__ __volatile__(
        "addi sp, sp, -13*4\n"  /* make room for 13 registers (ra + s0-s11)  */
        /* Save callee-saved registers */
        "sw ra,  0*4(sp)\n" "sw s0,  1*4(sp)\n" "sw s1,  2*4(sp)\n"
        "sw s2,  3*4(sp)\n" "sw s3,  4*4(sp)\n" "sw s4,  5*4(sp)\n"
        "sw s5,  6*4(sp)\n" "sw s6,  7*4(sp)\n" "sw s7,  8*4(sp)\n"
        "sw s8,  9*4(sp)\n" "sw s9, 10*4(sp)\n" "sw s10,11*4(sp)\n"
        "sw s11,12*4(sp)\n"
        "sw sp, (a0)\n"     /* store prev's new sp into *prev_sp             */
        "lw sp, (a1)\n"     /* load  next's saved sp from *next_sp           */
        /* Restore next's callee-saved registers */
        "lw ra,  0*4(sp)\n" "lw s0,  1*4(sp)\n" "lw s1,  2*4(sp)\n"
        "lw s2,  3*4(sp)\n" "lw s3,  4*4(sp)\n" "lw s4,  5*4(sp)\n"
        "lw s5,  6*4(sp)\n" "lw s6,  7*4(sp)\n" "lw s7,  8*4(sp)\n"
        "lw s8,  9*4(sp)\n" "lw s9, 10*4(sp)\n" "lw s10,11*4(sp)\n"
        "lw s11,12*4(sp)\n"
        "addi sp, sp, 13*4\n"  /* reclaim frame                             */
        "ret\n"                /* return to next's saved ra                 */
    );
}

/* ── Scheduler ───────────────────────────────────────────────────────────── */

/*
 * yield — cooperatively hand the CPU to the next runnable process.
 *
 * Round-robin: start searching from the process after current_proc.
 * Falls back to idle_proc if nothing is runnable.
 * Updates satp and sscratch to match the incoming process, then calls
 * switch_context to perform the actual register save/restore.
 */
void yield(void) {
    struct process *next = idle_proc;   /* default: run idle if nothing else */

    for (int i = 0; i < PROCS_MAX; i++) {
        /* Compute candidate index: search forward from current PID          */
        struct process *p = &procs[(current_proc->pid + i) % PROCS_MAX];
        if (p->state == PROC_RUNNABLE && p->pid > 0) {
            next = p;   /* found a runnable non-idle process                 */
            break;
        }
    }

    if (next == current_proc) return;   /* already the only runnable process  */

    struct process *prev = current_proc;
    current_proc = next;    /* update the global "who is running" pointer    */

    /* Switch to next's address space: write new satp with next's page table */
    __asm__ __volatile__(
        "sfence.vma\n"      /* flush TLB before changing address space       */
        "csrw satp, %[satp]\n"   /* install next process's root page table  */
        "sfence.vma\n"      /* flush TLB after — ensures new mappings visible */
        "csrw sscratch, %[ss]\n" /* update sscratch to next's kernel stack top */
        :: [satp] "r"(SATP_SV32 | ((uint32_t)next->page_table / PAGE_SIZE)),
           [ss]   "r"((uint32_t)&next->stack[sizeof(next->stack)])
    );

    switch_context(&prev->sp, &next->sp);  /* save prev's regs, load next's  */
}

/* ── Process creation ────────────────────────────────────────────────────── */

/*
 * create_process — allocate a PCB, page table, and stack; load the binary.
 *
 * The initial kernel stack is set up so that when the context switch first
 * restores this process, `ra` points to user_entry(), which will sret into
 * user mode at USER_BASE.
 *
 * Memory layout for a new process:
 *   kernel: identity-mapped (VA == PA) so kernel code works in any AS
 *   VirtIO: MMIO page identity-mapped (needed by kv_store flush)
 *   IPC buf: one page allocated, mapped user-accessible
 *   user image: copied page-by-page starting at USER_BASE
 */
struct process *create_process(const void *image, size_t image_size, uint8_t caps) {
    struct process *proc = NULL;
    /* Find an unused PCB slot in the global process table */
    for (int i = 0; i < PROCS_MAX; i++)
        if (procs[i].state == PROC_UNUSED) { proc = &procs[i]; break; }
    if (!proc) PANIC("no free process slots");

    /* Initialise the kernel stack with a fake context frame */
    uint32_t *sp = (uint32_t *)&proc->stack[sizeof(proc->stack)]; /* top of stack */
    for (int i = 0; i < 12; i++) *--sp = 0;          /* push zeros for s11–s0 */
    *--sp = (uint32_t)user_entry;                     /* push ra = user_entry  */

    /* Allocate and populate a fresh SV32 root page table */
    uint32_t *pt = (uint32_t *)alloc_pages(1);

    /* Identity-map all kernel + free RAM pages (R/W/X for supervisor mode) */
    for (paddr_t pa = (paddr_t)__kernel_base;
         pa < (paddr_t)__free_ram_end; pa += PAGE_SIZE)
        map_page(pt, pa, pa, PAGE_R | PAGE_W | PAGE_X);

    /* Map VirtIO MMIO region (needed for kv_store VirtIO flush calls) */
    map_page(pt, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W);

    /* Allocate the IPC rendezvous page and map it user-accessible */
    paddr_t ipc_pa = alloc_pages(1);
    proc->ipc_buf  = (struct ipc_msg *)ipc_pa;   /* kernel pointer to IPC buf */
    /* Map with PAGE_U so the user process can read/write it directly         */
    map_page(pt, ipc_pa, ipc_pa, PAGE_R | PAGE_W | PAGE_U);

    proc->ipc_notify_pid = -1;   /* no pending notification target initially  */

    /* Copy user binary into freshly allocated pages starting at USER_BASE   */
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
        paddr_t pg = alloc_pages(1);    /* one page per chunk of the binary    */
        /* Number of bytes to copy: min(PAGE_SIZE, remaining_bytes)            */
        size_t n = (PAGE_SIZE < image_size - off) ? PAGE_SIZE : image_size - off;
        memcpy((void *)pg, (const uint8_t *)image + off, n);   /* load binary  */
        /* Map as user-readable/writable/executable at USER_BASE + offset      */
        map_page(pt, USER_BASE + off, pg, PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }

    /* Fill in the rest of the PCB */
    proc->pid          = (int)(proc - procs) + 1;   /* 1-based PID            */
    proc->state        = PROC_RUNNABLE;              /* ready to run           */
    proc->capabilities = caps;                       /* granted capability bits */
    proc->sp           = (uint32_t)sp;              /* saved kernel stack ptr  */
    proc->page_table   = pt;                         /* root page-table ptr    */
    return proc;
}

/* ── Capability-gated IPC ────────────────────────────────────────────────── */

/*
 * do_ipc_call — kernel-mediated cross-service call.
 *
 * Flow:
 *   1. Identify target service PID from IPC type.
 *   2. Check caller's capability bitmask.
 *   3. Write request into target's ipc_buf.
 *   4. If target is PROC_WAITING (blocked in SYS_IPC_WAIT), wake it up.
 *   5. Block caller (PROC_BLOCKED) and yield.
 *   6. Target runs, handles request, calls SYS_IPC_NOTIFY to wake caller.
 *   7. Caller resumes, copies reply, returns status.
 */
static int do_ipc_call(uint8_t type,
                        const uint8_t *payload, uint16_t plen,
                        uint8_t *reply, uint16_t *rlen) {
    int target_pid;
    uint8_t req_cap;

    /* Map IPC type → target PID and required capability bit */
    switch (type) {
        case IPC_CRYPTO_HASH:
        case IPC_CRYPTO_SIGN:
        case IPC_CRYPTO_VERIFY:
            target_pid = pid_crypto;   /* crypto_service PID                 */
            req_cap    = CAP_CRYPTO;   /* caller needs CAP_CRYPTO            */
            break;
        case IPC_KV_PUT:
        case IPC_KV_GET:
            target_pid = pid_kv;       /* kv_store PID                       */
            req_cap    = CAP_KVSTORE;
            break;
        case IPC_NET_BROADCAST:
        case IPC_NET_FETCH_BLOCK:
            target_pid = pid_network;  /* network_service PID                */
            req_cap    = CAP_NETWORK;
            break;
        default:
            return IPC_STATUS_ERROR;   /* unknown IPC type — reject           */
    }

    /* Capability check: deny if caller doesn't hold the required bit        */
    if (!(current_proc->capabilities & req_cap)) {
        printf("ipc: pid %d denied (cap 0x%x, type 0x%x)\n",
               current_proc->pid, req_cap, type);
        return IPC_STATUS_DENIED;
    }

    /* Validate target PID */
    if (target_pid < 1 || target_pid > PROCS_MAX) {
        printf("ipc: service not registered (type 0x%x)\n", type);
        return IPC_STATUS_ERROR;
    }

    struct process *tgt = &procs[target_pid - 1];  /* 1-based → 0-based      */
    if (!tgt->ipc_buf) return IPC_STATUS_ERROR;     /* sanity: must have IPC buf */

    /* Write request into target's IPC buffer */
    tgt->ipc_buf->type = type;             /* IPC type field signals pending  */
    tgt->ipc_buf->status = 0;              /* clear previous status           */
    if (plen > IPC_VALUE_MAX) plen = IPC_VALUE_MAX;  /* clamp payload size   */
    tgt->ipc_buf->payload_len = plen;
    if (payload) memcpy(tgt->ipc_buf->payload, payload, plen);

    /* Record who to wake when the server finishes (for SYS_IPC_NOTIFY)      */
    tgt->ipc_notify_pid = current_proc->pid;

    /* Wake target if it's sleeping in SYS_IPC_WAIT                          */
    if (tgt->state == PROC_WAITING)
        tgt->state = PROC_RUNNABLE;   /* target can now run to handle request */

    /* Block ourselves until the server calls SYS_IPC_NOTIFY                 */
    current_proc->state = PROC_BLOCKED;
    yield();   /* give CPU to target (or whoever is next in round-robin)     */

    /* ── Execution resumes here after SYS_IPC_NOTIFY re-wakes us ── */
    current_proc->state = PROC_RUNNABLE;   /* we are runnable again          */

    /* Copy reply payload back to caller's buffer */
    if (reply && rlen) {
        *rlen = tgt->ipc_buf->payload_len;
        if (*rlen > IPC_VALUE_MAX) *rlen = IPC_VALUE_MAX;   /* bounds check   */
        memcpy(reply, tgt->ipc_buf->payload, *rlen);
    }
    return tgt->ipc_buf->status;   /* return server's status code            */
}

/* ── Syscall handler ─────────────────────────────────────────────────────── */

/*
 * handle_syscall — dispatch ecall to the appropriate kernel service.
 *
 * Called with a pointer to the trap_frame saved in kernel_entry.
 * Syscall number is in f->a3; arguments in f->a0, f->a1, f->a2, f->a4.
 * Return value is written to f->a0.
 */
void handle_syscall(struct trap_frame *f) {
    switch (f->a3) {   /* dispatch on syscall number in register a3          */

    case SYS_PUTCHAR:
        putchar((char)f->a0);   /* emit one character via SBI console        */
        break;

    case SYS_GETCHAR:
        /* Spin-yield until a character is available from the console        */
        while (1) {
            long c = getchar();
            if (c >= 0) { f->a0 = c; break; }   /* got a character           */
            yield();                              /* no data yet — yield       */
        }
        break;

    case SYS_EXIT:
        printf("kernel: pid %d exited\n", current_proc->pid);
        current_proc->state = PROC_EXITED;   /* mark process done            */
        yield();                              /* switch away — never return   */
        PANIC("unreachable");

    case SYS_YIELD:
        yield();   /* cooperative yield — let other processes run            */
        break;

    /* ── File I/O ── */
    case SYS_READFILE:
    case SYS_WRITEFILE: {
        const char *name = (const char *)f->a0;  /* a0 = filename ptr        */
        char       *buf  = (char *)f->a1;         /* a1 = data buffer ptr    */
        int         len  = f->a2;                 /* a2 = byte count         */
        struct file *file = fs_lookup(name);
        if (!file) { printf("fs: not found: %s\n", name); f->a0 = -1; break; }
        if (len > (int)sizeof(file->data)) len = file->size;   /* clamp     */
        if (f->a3 == SYS_WRITEFILE) {
            memcpy(file->data, buf, len);   /* copy data into in-memory file */
            file->size = len;               /* update stored size            */
            fs_flush();                     /* persist to VirtIO disk        */
        } else {
            memcpy(buf, file->data, len);   /* copy data out to caller buf   */
        }
        f->a0 = len;   /* return number of bytes transferred                 */
        break;
    }

    /* ── Crypto IPC syscalls ── */
    case SYS_CRYPTO_HASH: {
        /* a0=data ptr, a1=data len, a2=output ptr                           */
        uint8_t *out = (uint8_t *)f->a2;
        uint16_t olen = 0;
        int rc = do_ipc_call(IPC_CRYPTO_HASH,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              out, &olen);
        f->a0 = (rc == IPC_STATUS_OK) ? (int)olen : -rc;  /* positive=len, negative=err */
        break;
    }

    case SYS_CRYPTO_SIGN: {
        /* a0=payload ptr, a1=payload len, a2=sig output ptr                 */
        uint8_t *out = (uint8_t *)f->a2;
        uint16_t olen = 0;
        int rc = do_ipc_call(IPC_CRYPTO_SIGN,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              out, &olen);
        f->a0 = (rc == IPC_STATUS_OK) ? (int)olen : -rc;
        break;
    }

    /* ── KV store IPC syscalls ── */
    case SYS_KV_PUT: {
        /* a0=key ptr, a1=klen, a2=val ptr, a4=vlen
           Wire format: [klen:2][vlen:2][key:klen][val:vlen]               */
        uint8_t  buf[IPC_KEY_MAX + IPC_VALUE_MAX + 4];
        uint16_t klen = (uint16_t)f->a1;
        uint16_t vlen = (uint16_t)f->a4;
        if (klen > IPC_KEY_MAX)               klen = IPC_KEY_MAX;
        if (vlen > IPC_VALUE_MAX - klen - 4)  vlen = IPC_VALUE_MAX - klen - 4;
        buf[0] = (klen >> 8);    /* klen high byte                           */
        buf[1] = (klen & 0xFF);  /* klen low byte                            */
        buf[2] = (vlen >> 8);    /* vlen high byte                           */
        buf[3] = (vlen & 0xFF);  /* vlen low byte                            */
        memcpy(&buf[4],          /* key bytes start at offset 4              */
               (const void *)f->a0, klen);
        memcpy(&buf[4 + klen],   /* value bytes follow the key               */
               (const void *)f->a2, vlen);
        f->a0 = do_ipc_call(IPC_KV_PUT, buf, 4 + klen + vlen, NULL, NULL);
        break;
    }

    case SYS_KV_GET: {
        /* a0=key ptr, a1=klen, a2=val output ptr
           Wire format: [klen:2][key:klen]                                  */
        uint8_t  buf[IPC_KEY_MAX + 2];
        uint16_t klen = (uint16_t)f->a1;
        if (klen > IPC_KEY_MAX) klen = IPC_KEY_MAX;
        buf[0] = (klen >> 8);    /* klen high byte                           */
        buf[1] = (klen & 0xFF);  /* klen low byte                            */
        memcpy(&buf[2], (const void *)f->a0, klen);  /* key bytes            */
        uint8_t reply[IPC_VALUE_MAX];
        uint16_t rlen = 0;
        int rc = do_ipc_call(IPC_KV_GET, buf, 2 + klen, reply, &rlen);
        if (rc == IPC_STATUS_OK) {
            memcpy((void *)f->a2, reply, rlen);  /* copy value to caller buf */
            f->a0 = rlen;        /* return value length                      */
        } else {
            f->a0 = -rc;         /* return negative error code               */
        }
        break;
    }

    /* ── Network IPC syscalls ── */
    case SYS_NET_BROADCAST: {
        /* a0=tx ptr, a1=tx_len                                              */
        int rc = do_ipc_call(IPC_NET_BROADCAST,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              NULL, NULL);
        f->a0 = rc;   /* IPC_STATUS_OK or error code                         */
        break;
    }

    case SYS_NET_FETCH: {
        /* a0=output buffer ptr                                              */
        uint8_t  blk[IPC_VALUE_MAX];
        uint16_t blen = 0;
        int rc = do_ipc_call(IPC_NET_FETCH_BLOCK, NULL, 0, blk, &blen);
        if (rc == IPC_STATUS_OK) {
            memcpy((void *)f->a0, blk, blen);  /* copy block to caller       */
            f->a0 = blen;        /* return block length                      */
        } else {
            f->a0 = -rc;         /* return negative error code               */
        }
        break;
    }

    /* ── Event-driven IPC: server side ── */
    case SYS_IPC_WAIT: {
        /*
         * Server calls this to sleep until a client delivers a request.
         * Sets state to PROC_WAITING, then yields.
         * do_ipc_call will set us back to PROC_RUNNABLE when work arrives.
         */
        current_proc->state = PROC_WAITING;   /* enter sleeping-server state */
        yield();                               /* give CPU to others          */
        /* We wake up here when do_ipc_call sets us RUNNABLE                 */
        f->a0 = 0;   /* return 0 = request is ready in ipc_buf               */
        break;
    }

    case SYS_IPC_NOTIFY: {
        /*
         * Server calls this after writing the reply into ipc_buf.
         * Finds the blocked caller (stored in ipc_notify_pid) and
         * marks it RUNNABLE so it can collect the reply on its next turn.
         */
        int notify_pid = current_proc->ipc_notify_pid;
        current_proc->ipc_notify_pid = -1;   /* clear pending notification   */
        if (notify_pid >= 1 && notify_pid <= PROCS_MAX) {
            struct process *caller = &procs[notify_pid - 1];
            if (caller->state == PROC_BLOCKED)
                caller->state = PROC_RUNNABLE;  /* wake the blocked caller   */
        }
        f->a0 = 0;   /* notify succeeded                                     */
        break;
    }

    /* ── Hardware entropy ── */
    case SYS_TRNG: {
        /*
         * a0 = output buffer pointer (user-space)
         * a1 = number of bytes requested
         * Fills the buffer with entropy from RISC-V seed CSR or fallback.
         */
        uint8_t *out = (uint8_t *)f->a0;
        size_t   n   = (size_t)f->a1;
        if (n > 64) n = 64;   /* cap at 64 bytes per syscall for safety      */
        trng_fill(out, n);
        f->a0 = (int)n;       /* return number of bytes written               */
        break;
    }

    default:
        PANIC("unexpected syscall a3=0x%x", f->a3);
    }
}

/*
 * handle_trap — called from kernel_entry with the saved trap frame.
 *
 * Reads scause to distinguish ecall from other traps.
 * For ecall: dispatch to handle_syscall, then advance sepc past the ecall
 * instruction (every RISC-V instruction is at least 4 bytes in rv32ima).
 * Any other trap is a fatal kernel error.
 */
void handle_trap(struct trap_frame *f) {
    uint32_t scause = READ_CSR(scause);  /* reason for the trap               */
    uint32_t stval  = READ_CSR(stval);   /* trap value (bad address for faults)*/
    uint32_t sepc   = READ_CSR(sepc);    /* PC that caused the trap            */

    if (scause == SCAUSE_ECALL) {
        handle_syscall(f);   /* dispatch the syscall                          */
        sepc += 4;           /* advance past the ecall instruction (4 bytes)  */
    } else {
        /* Any non-ecall trap in this kernel is unrecoverable */
        PANIC("trap scause=0x%x stval=0x%x sepc=0x%x", scause, stval, sepc);
    }
    WRITE_CSR(sepc, sepc);   /* update sepc so sret returns to the next instr */
}

/* ── Boot ─────────────────────────────────────────────────────────────────── */

/*
 * kernel_main — C entry point after the assembly boot stub sets up the stack.
 *
 * Initialisation sequence:
 *   1. Zero BSS (linker guarantees layout; .bss is not in ELF load image).
 *   2. Install trap vector.
 *   3. Initialise VirtIO block device.
 *   4. Load TAR filesystem from disk.
 *   5. Create idle process (pid 0).
 *   6. Spawn well-known services with their capability masks.
 *   7. Yield into the scheduler loop.
 */
void kernel_main(void) {
    /* 1. Zero BSS — variables declared but not initialised need zero storage */
    memset(__bss, 0, (size_t)__bss_end - (size_t)__bss);

    printf("\n");
    printf("==========================================================\n");
    printf("  Protheus OS — Microkernel Blockchain Runtime\n");
    printf("  Author: m26steph@uwaterloo.ca\n");
    printf("  Credits: Nicolae Carabut (Dispatch Labs)\n");
    printf("==========================================================\n\n");

    /* 2. Install the trap vector (stvec must point to 4-byte-aligned fn)    */
    WRITE_CSR(stvec, (uint32_t)kernel_entry);

    /* 3. Initialise VirtIO block device and read its capacity               */
    virtio_blk_init();

    /* 4. Load TAR disk image into in-memory file table                      */
    fs_init();

    /* 5. Create the idle process (runs when nothing else is runnable)       */
    idle_proc      = create_process(NULL, 0, CAP_NONE);
    idle_proc->pid = 0;          /* give idle process pid 0 (special case)   */
    current_proc   = idle_proc;  /* start with idle as "current"             */

    /* 6. Spawn services in dependency order:
          crypto first (monerod needs it), then kv, network, monerod last.  */
    struct { const char *name; uint8_t caps; } svcs[] = {
        { "crypto_service",  CAP_LOG },
        { "kv_store",        CAP_LOG },
        { "network_service", CAP_LOG | CAP_TIMER },
        { "monerod",         CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK |
                             CAP_TIMER  | CAP_LOG },
        { NULL, 0 }   /* sentinel */
    };

    for (int i = 0; svcs[i].name; i++) {
        struct file *f = fs_lookup(svcs[i].name);
        if (!f) {
            printf("kernel: WARNING: %s not found on disk\n", svcs[i].name);
            continue;
        }
        struct process *p = create_process(f->data, f->size, svcs[i].caps);
        printf("kernel: spawned %s pid=%d caps=0x%x\n",
               svcs[i].name, p->pid, p->capabilities);

        /* Record well-known PIDs so do_ipc_call can route messages         */
        if (i == 0) pid_crypto  = p->pid;
        if (i == 1) pid_kv      = p->pid;
        if (i == 2) pid_network = p->pid;
    }

    /* Fallback: launch a debug shell if monerod binary is absent            */
    if (!fs_lookup("monerod")) {
        create_process(_binary_shell_bin_start,
                       (size_t)_binary_shell_bin_size, CAP_ALL);
        printf("kernel: no monerod image — debug shell started\n");
    }

    /* 7. Enter the scheduler; idle_proc will run when nothing else can      */
    yield();
    PANIC("idle reached — scheduler broken");   /* should never happen       */
}

/*
 * boot — very first code that runs after OpenSBI hands control to the kernel.
 * Placed in .text.boot so the linker script keeps it at the entry point.
 * Sets up the stack pointer, then jumps to kernel_main.
 */
__attribute__((section(".text.boot"))) __attribute__((naked))
void boot(void) {
    __asm__ __volatile__(
        "mv sp, %[top]\n"   /* load stack top address into sp                */
        "j kernel_main\n"   /* jump to C entry point (no return)             */
        :: [top] "r"(__stack_top)
    );
}
