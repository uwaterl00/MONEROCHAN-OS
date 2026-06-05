/*
 * kernel.c — Protheus OS main kernel.
 *
 * Implements (in order of boot execution):
 *   1. boot()          — naked entry at 0x80200000; sets stack pointer.
 *   2. kernel_main()   — BSS clear, device init, service spawn, idle loop.
 *   3. virtio_blk_init — legacy VirtIO-blk MMIO handshake.
 *   4. fs_init/flush   — load/save ustar TAR image from VirtIO disk.
 *   5. create_process  — allocate a process slot, build SV32 page tables.
 *   6. yield           — cooperative round-robin scheduler.
 *   7. switch_context  — naked callee-saved register swap.
 *   8. kernel_entry    — naked trap entry; saves all registers, calls handle_trap.
 *   9. handle_trap     — dispatches ecall to handle_syscall; panics on other traps.
 *  10. handle_syscall  — implements all SYS_* numbers including capability-gated IPC.
 *  11. do_ipc_call     — capability check + synchronous blocking IPC rendezvous.
 *
 * Architecture: RISC-V rv32ima | SV32 paging | OpenSBI | VirtIO-blk (legacy)
 *
 * Author:  m26steph@uwaterloo.ca
 */

#include "kernel.h"    /* all struct/constant definitions */
#include "common.h"    /* types, PANIC, READ_CSR, WRITE_CSR */

/* ── Linker-script symbols ──────────────────────────────────────────────── */
/* These are declared by kernel.ld; the C compiler sees them as extern char
 * arrays so we can take their address as a physical address.               */
extern char __kernel_base[];   /* physical start of kernel text (0x80200000) */
extern char __stack_top[];     /* top of the 128 KiB kernel stack            */
extern char __bss[];           /* start of .bss section                      */
extern char __bss_end[];       /* end   of .bss section                      */
extern char __free_ram[];      /* start of physical heap (above stack)       */
extern char __free_ram_end[];  /* end   of physical heap (0x88000000)        */

/* Symbol created by objcopy --rename-section .data=.shell shell.bin        */
extern char _binary_shell_bin_start[]; /* start address of embedded shell binary */
extern char _binary_shell_bin_size[];  /* size  symbol injected by objcopy         */

/* ── Global kernel state ────────────────────────────────────────────────── */
struct process  procs[PROCS_MAX];  /* all process control blocks               */
struct process *current_proc;      /* pointer to currently running process      */
struct process *idle_proc;         /* the idle process (pid=0)                  */

/* PIDs of the three services that can be IPC targets.  Set during boot.    */
static int pid_crypto  = -1;       /* PID of crypto_service                     */
static int pid_kv      = -1;       /* PID of kv_store                           */
static int pid_network = -1;       /* PID of network_service                    */

/* ══════════════════════════════════════════════════════════════════════════
 * PHYSICAL MEMORY ALLOCATOR
 *
 * Simple bump allocator over the free RAM region defined by the linker
 * script (__free_ram .. __free_ram_end).  Memory is never freed.
 * Every allocation is zeroed by memset to avoid stale data in page tables
 * and process stacks.
 * ══════════════════════════════════════════════════════════════════════════ */
paddr_t alloc_pages(uint32_t n) {
    /* 'next' is static so it persists across calls; first call initialises it */
    static paddr_t next = (paddr_t)__free_ram;  /* bump pointer starts at heap base */
    paddr_t base = next;                         /* record allocation start address  */
    next += n * PAGE_SIZE;                       /* advance bump pointer by n pages  */
    if (next > (paddr_t)__free_ram_end)          /* ran past the end of physical RAM */
        PANIC("out of physical memory");
    memset((void *)base, 0, n * PAGE_SIZE);      /* zero the allocation (safety)     */
    return base;                                 /* return physical address          */
}

/* ══════════════════════════════════════════════════════════════════════════
 * SV32 PAGE-TABLE MANAGEMENT
 *
 * SV32 uses a two-level radix page table.
 *   Level-1 table  (table1): 1024 entries, indexed by vaddr[31:22] (VPN[1]).
 *   Level-0 table  (table0): 1024 entries, indexed by vaddr[21:12] (VPN[0]).
 *   Leaf PTE bits  [31:10]: Physical Page Number (PPN).
 *   Leaf PTE bits  [9:0]:   Flags (V/R/W/X/U/...).
 *
 * PPN encoding: (physical_addr / PAGE_SIZE) << 10
 * Table pointer: (pa / PAGE_SIZE) << 10 | PAGE_V  (non-leaf PTE)
 * ══════════════════════════════════════════════════════════════════════════ */
void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
    /* Assert both addresses are page-aligned (required by the hardware) */
    if (!is_aligned(vaddr,  PAGE_SIZE)) PANIC("unaligned vaddr  0x%x", vaddr);
    if (!is_aligned(paddr,  PAGE_SIZE)) PANIC("unaligned paddr  0x%x", paddr);

    /* Extract VPN[1]: bits [31:22] of vaddr — index into the level-1 table */
    uint32_t vpn1 = (vaddr >> 22) & 0x3ff;

    /* If the level-1 entry is not yet valid, allocate a new level-0 table */
    if (!(table1[vpn1] & PAGE_V)) {
        uint32_t pt = alloc_pages(1);             /* one page for the L0 table        */
        /* Non-leaf PTE: PPN of L0 table, PAGE_V set, no R/W/X (hardware rule) */
        table1[vpn1] = ((pt / PAGE_SIZE) << 10) | PAGE_V;
    }

    /* Extract VPN[0]: bits [21:12] of vaddr — index into the level-0 table */
    uint32_t vpn0 = (vaddr >> 12) & 0x3ff;

    /* Derive pointer to the level-0 table from the level-1 PTE */
    uint32_t *table0 = (uint32_t *)((table1[vpn1] >> 10) * PAGE_SIZE);

    /* Write the leaf PTE: PPN of physical frame + caller-supplied flags + V */
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

/* ══════════════════════════════════════════════════════════════════════════
 * SBI (Supervisor Binary Interface)
 *
 * OpenSBI runs in M-mode and exposes services to S-mode via ecall.
 * The calling convention follows the SBI specification v0.2:
 *   a7 = extension ID (EID)
 *   a6 = function  ID (FID)
 *   a0-a5 = arguments
 *   Returns: a0 = error, a1 = value
 * ══════════════════════════════════════════════════════════════════════════ */
struct sbiret sbi_call(long a0, long a1, long a2, long a3, long a4,
                       long a5, long fid, long eid) {
    /* Load each argument into the exact register the SBI spec requires */
    register long _a0 __asm__("a0") = a0;  /* first  argument / return error   */
    register long _a1 __asm__("a1") = a1;  /* second argument / return value   */
    register long _a2 __asm__("a2") = a2;  /* third  argument                  */
    register long _a3 __asm__("a3") = a3;  /* fourth argument                  */
    register long _a4 __asm__("a4") = a4;  /* fifth  argument                  */
    register long _a5 __asm__("a5") = a5;  /* sixth  argument                  */
    register long _a6 __asm__("a6") = fid; /* function ID                      */
    register long _a7 __asm__("a7") = eid; /* extension ID                     */
    /* ecall traps into M-mode OpenSBI; outputs overwrite a0/a1 */
    __asm__ __volatile__("ecall"
                         : "=r"(_a0), "=r"(_a1)
                         : "r"(_a0), "r"(_a1), "r"(_a2), "r"(_a3),
                           "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7)
                         : "memory");
    return (struct sbiret){ .error = _a0, .value = _a1 };
}

/* putchar — emit one character via SBI console putchar (EID=1, legacy) */
void putchar(char ch) {
    sbi_call(ch, 0, 0, 0, 0, 0, 0, 1); /* a0=char, eid=1 (legacy console) */
}

/* getchar — poll SBI console for one character; returns -1 if none ready */
long getchar(void) {
    return sbi_call(0, 0, 0, 0, 0, 0, 0, 2).error; /* eid=2 = console getchar */
}

/* ══════════════════════════════════════════════════════════════════════════
 * VIRTIO BLOCK DEVICE  (legacy MMIO interface, version 1)
 *
 * Initialisation sequence (from the VirtIO spec §3.1.1):
 *   1. Reset the device (write 0 to status).
 *   2. ACK: tell device OS knows about it.
 *   3. DRIVER: tell device OS can drive it.
 *   4. Set PAGE_SIZE for the legacy queue address calculation.
 *   5. Set up virtqueue 0 (the request queue).
 *   6. DRIVER_OK: mark init complete.
 * ══════════════════════════════════════════════════════════════════════════ */

/* Module-level state for the single VirtIO block device */
static struct virtio_virtq   *blk_request_vq;   /* virtqueue 0 pointer           */
static struct virtio_blk_req *blk_req;           /* request buffer pointer        */
static paddr_t                blk_req_paddr;     /* physical address of blk_req   */
static uint64_t               blk_capacity;      /* device capacity in bytes      */

/* Read a 32-bit MMIO register at VIRTIO_BLK_PADDR + off */
static uint32_t vreg32(unsigned off) {
    return *(volatile uint32_t *)(VIRTIO_BLK_PADDR + off); /* volatile prevents optimisation away */
}

/* Read a 64-bit MMIO register (two 32-bit reads; little-endian) */
static uint64_t vreg64(unsigned off) {
    return *(volatile uint64_t *)(VIRTIO_BLK_PADDR + off); /* 64-bit aligned access */
}

/* Write a 32-bit value to MMIO register */
static void vwreg32(unsigned off, uint32_t v) {
    *(volatile uint32_t *)(VIRTIO_BLK_PADDR + off) = v; /* volatile write always reaches device */
}

/* Read-modify-write: OR in bits v to register off */
static void vor32(unsigned off, uint32_t v) {
    vwreg32(off, vreg32(off) | v); /* read, OR, write back */
}

/* virtq_kick — post descriptor chain head `desc` to the device and wait.
 *
 * The kick sequence:
 *   1. Write desc index into avail.ring[avail.index % QUEUE_SIZE].
 *   2. Increment avail.index (device sees new entry on next check).
 *   3. Memory barrier: ensure the ring write is visible before notify.
 *   4. Write queue index to QUEUE_NOTIFY register (kicks the device).
 *   5. Increment our last_used_index to match expected completion.
 *   6. Spin until used.index matches (device signals completion by incrementing it).
 */
static void virtq_kick(struct virtio_virtq *vq, int desc) {
    /* Post the descriptor chain head to the available ring */
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc;
    vq->avail.index++;                    /* advance available index                    */
    __sync_synchronize();                 /* full memory barrier before notifying device */
    vwreg32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index); /* kick: tell device to check queue */
    vq->last_used_index++;                /* we expect one more completion               */
}

/* virtq_init — allocate and register a single virtqueue with the device */
static struct virtio_virtq *virtq_init(unsigned idx) {
    /* Allocate physically contiguous pages for the queue struct */
    paddr_t pa = alloc_pages(
        align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *)pa;
    vq->queue_index = idx;                    /* remember which queue this is       */
    /* used_index points into the device-written used ring */
    vq->used_index  = (volatile uint16_t *)&vq->used.index;

    /* Tell the device which queue we are configuring */
    vwreg32(VIRTIO_REG_QUEUE_SEL, idx);
    /* Tell the device how many descriptors our ring has */
    vwreg32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);
    /* Give the device the page frame number of our queue struct (legacy: pa/PAGE_SIZE) */
    vwreg32(VIRTIO_REG_QUEUE_PFN, pa / PAGE_SIZE);
    return vq;
}

/* virtio_blk_init — full device initialisation; called once from kernel_main */
void virtio_blk_init(void) {
    /* Sanity-check the magic number to confirm a real VirtIO device */
    if (vreg32(VIRTIO_REG_MAGIC)     != 0x74726976) PANIC("virtio: bad magic (not 'virt')");
    /* Version 1 = legacy MMIO interface */
    if (vreg32(VIRTIO_REG_VERSION)   != 1)          PANIC("virtio: version != 1 (not legacy)");
    /* Device type 2 = block device */
    if (vreg32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK) PANIC("virtio: not a block device");

    /* Step 1: reset — write 0 to clear any previous state */
    vwreg32(VIRTIO_REG_DEVICE_STATUS, 0);
    /* Step 2: set ACK bit — we acknowledge the device */
    vor32  (VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    /* Step 3: set DRIVER bit — we know how to drive it */
    vor32  (VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    /* Legacy requirement: tell device what page size the driver uses */
    vwreg32(VIRTIO_REG_PAGE_SIZE, PAGE_SIZE);
    /* Step 5: allocate and register virtqueue 0 */
    blk_request_vq = virtq_init(0);
    /* Step 6: set DRIVER_OK — initialisation complete */
    vwreg32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

    /* Read device capacity: config offset 0 = number of 512-byte sectors */
    blk_capacity  = vreg64(VIRTIO_REG_DEVICE_CONFIG) * SECTOR_SIZE;
    /* Allocate and pin the request buffer (one page, always physically mapped) */
    blk_req_paddr = alloc_pages(
        align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
    blk_req = (struct virtio_blk_req *)blk_req_paddr;
    printf("virtio-blk: %u bytes capacity\n", (unsigned)blk_capacity);
}

/* read_write_disk — issue a single-sector read or write request.
 *
 * Uses a three-descriptor chain:
 *   desc[0] — request header (type + sector number): driver-readable
 *   desc[1] — data buffer (SECTOR_SIZE bytes): direction depends on request
 *   desc[2] — status byte:                    device-writable
 *
 * The function spins until the device increments used.index, indicating
 * completion (cooperative kernel; no interrupt handler needed).
 */
void read_write_disk(void *buf, unsigned sector, int is_write) {
    /* Bounds check: refuse sectors beyond the device capacity */
    if (sector >= blk_capacity / SECTOR_SIZE) {
        printf("virtio: sector %u out of range\n", sector);
        return;
    }

    /* Fill in the request header */
    blk_req->sector = sector;                          /* which 512-byte sector */
    blk_req->type   = is_write ? VIRTIO_BLK_T_OUT     /* OUT = write to device */
                               : VIRTIO_BLK_T_IN;     /* IN  = read from device */

    /* For writes: copy caller's data into the DMA buffer before kicking */
    if (is_write)
        memcpy(blk_req->data, buf, SECTOR_SIZE);

    struct virtio_virtq *vq = blk_request_vq; /* use the single request queue */

    /* desc[0]: the request header (type, reserved, sector) — device reads this */
    vq->descs[0].addr  = blk_req_paddr;                        /* physical address */
    vq->descs[0].len   = sizeof(uint32_t) * 2 + sizeof(uint64_t); /* type+reserved+sector */
    vq->descs[0].flags = VIRTQ_DESC_F_NEXT;                    /* chain to next    */
    vq->descs[0].next  = 1;                                    /* → desc[1]        */

    /* desc[1]: the data buffer — device writes on IN, reads on OUT */
    vq->descs[1].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    vq->descs[1].len   = SECTOR_SIZE;
    /* WRITE flag on descriptor means device-writable (i.e. set for reads) */
    vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    vq->descs[1].next  = 2;                                    /* → desc[2]        */

    /* desc[2]: status byte — always device-writable; no chaining */
    vq->descs[2].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    vq->descs[2].len   = sizeof(uint8_t);
    vq->descs[2].flags = VIRTQ_DESC_F_WRITE;                   /* device writes result */

    /* Post chain (head = desc[0]) and wait for completion */
    virtq_kick(vq, 0);
    /* Spin until the device increments used.index to match our last_used_index */
    while (vq->last_used_index != *vq->used_index)
        ;   /* busy wait — acceptable in a cooperative, single-hart kernel */

    /* Check the status byte written by the device */
    if (blk_req->status != 0)
        printf("virtio: sector %u I/O error (status=%d)\n", sector, blk_req->status);

    /* For reads: copy DMA buffer into caller's buffer after completion */
    if (!is_write)
        memcpy(buf, blk_req->data, SECTOR_SIZE);
}

/* ══════════════════════════════════════════════════════════════════════════
 * TAR FILESYSTEM
 *
 * The service binaries are packed into a ustar TAR image at build time and
 * linked into the kernel image as the .disk section.  At runtime fs_init()
 * reads the disk image into RAM and parses the TAR headers.  fs_flush()
 * writes modified files back to disk.
 *
 * Only FILES_MAX files and FILE_DATA_MAX bytes per file are supported.
 * This is sufficient to store four small service binaries.
 * ══════════════════════════════════════════════════════════════════════════ */

static struct file files[FILES_MAX];              /* in-RAM file table                 */
static uint8_t     disk[DISK_MAX_SIZE];           /* raw sector buffer for the disk image */

/* oct2int — convert `len`-character octal ASCII string to integer */
static int oct2int(char *oct, int len) {
    int v = 0;
    for (int i = 0; i < len; i++) {
        if (oct[i] < '0' || oct[i] > '7') break; /* stop at non-octal char */
        v = v * 8 + (oct[i] - '0');               /* shift left octal + add digit */
    }
    return v;
}

/* fs_flush — serialise the in-RAM file table back to the TAR disk image.
 * Called after any write syscall so the disk stays consistent.             */
void fs_flush(void) {
    /* Zero the disk buffer before rebuilding it from scratch */
    memset(disk, 0, sizeof(disk));
    unsigned off = 0;  /* byte offset into the disk[] buffer */

    for (int i = 0; i < FILES_MAX; i++) {
        struct file *f = &files[i];
        if (!f->in_use) continue;                  /* skip empty slots */

        /* Write a TAR header at the current offset */
        struct tar_header *h = (struct tar_header *)&disk[off];
        memset(h, 0, sizeof(*h));                  /* zero the header first */
        strcpy(h->name, f->name);                  /* file name field */
        strcpy(h->mode, "000644");                 /* permissions: rw-r--r-- */
        strcpy(h->magic, "ustar");                 /* POSIX ustar magic */
        strcpy(h->version, "00");                  /* version field */
        h->type = '0';                             /* '0' = regular file */

        /* Encode file size in 11-digit octal ASCII (right-justified) */
        int sz = f->size;
        for (int j = sizeof(h->size) - 1; j >= 0; j--) {
            h->size[j] = '0' + (sz % 8);           /* extract lowest octal digit */
            sz /= 8;                                /* shift right one octal place */
        }

        /* Compute TAR checksum: sum of all header bytes, treating checksum as spaces */
        int ck = ' ' * (int)sizeof(h->checksum);   /* pretend checksum field is spaces */
        for (unsigned j = 0; j < sizeof(struct tar_header); j++)
            ck += (unsigned char)disk[off + j];     /* sum every header byte */
        /* Write checksum as 6 octal digits */
        for (int j = 5; j >= 0; j--) {
            h->checksum[j] = '0' + (ck % 8);
            ck /= 8;
        }

        /* Copy file data immediately after the header */
        memcpy(h->data, f->data, f->size);
        /* Advance offset by header + data, rounded up to sector boundary */
        off += align_up(sizeof(struct tar_header) + f->size, SECTOR_SIZE);
    }

    /* Write every sector of the disk[] buffer to the VirtIO device */
    for (unsigned s = 0; s < sizeof(disk) / SECTOR_SIZE; s++)
        read_write_disk(&disk[s * SECTOR_SIZE], s, /*is_write=*/1);
    printf("fs: flushed %u bytes to disk\n", (unsigned)sizeof(disk));
}

/* fs_init — read the TAR disk image and populate the in-RAM file table */
void fs_init(void) {
    /* Read every sector of the disk image into the disk[] buffer */
    for (unsigned s = 0; s < sizeof(disk) / SECTOR_SIZE; s++)
        read_write_disk(&disk[s * SECTOR_SIZE], s, /*is_write=*/0);

    unsigned off = 0;  /* byte offset into disk[] */
    for (int i = 0; i < FILES_MAX; i++) {
        struct tar_header *h = (struct tar_header *)&disk[off];
        if (h->name[0] == '\0') break;             /* double-NUL block = end of archive */
        /* Validate the magic field to catch corrupt images */
        if (strcmp(h->magic, "ustar") != 0)
            PANIC("fs: bad TAR magic \"%s\" at offset %u", h->magic, off);
        /* Decode the file size from octal ASCII */
        int sz = oct2int(h->size, sizeof(h->size));
        if (sz > FILE_DATA_MAX) sz = FILE_DATA_MAX; /* clamp to our per-file limit */
        /* Populate the in-RAM slot */
        struct file *f = &files[i];
        f->in_use = true;
        strncpy(f->name, h->name, 99);
        f->name[99] = '\0';                         /* ensure NUL termination */
        memcpy(f->data, h->data, sz);
        f->size = sz;
        printf("fs: '%s' (%d bytes)\n", f->name, f->size);
        /* Advance past this entry: header + data rounded to sector boundary */
        off += align_up(sizeof(struct tar_header) + sz, SECTOR_SIZE);
    }
}

/* fs_lookup — find a file by name; returns NULL if not found */
struct file *fs_lookup(const char *name) {
    for (int i = 0; i < FILES_MAX; i++)
        if (files[i].in_use && strcmp(files[i].name, name) == 0)
            return &files[i];
    return NULL;  /* not found */
}

/* ══════════════════════════════════════════════════════════════════════════
 * TRAP ENTRY / EXIT  (naked functions — no prologue/epilogue generated)
 *
 * kernel_entry is installed as the stvec handler.  On any S-mode trap:
 *   1. Swap sp ↔ sscratch to get the kernel stack pointer.
 *   2. Save all caller-saved and callee-saved registers onto the kernel stack.
 *   3. Call handle_trap(trap_frame *).
 *   4. Restore all registers and sret back to user mode.
 *
 * sscratch holds the TOP of the current process's kernel stack between traps.
 * ══════════════════════════════════════════════════════════════════════════ */
__attribute__((naked)) __attribute__((aligned(4)))
void kernel_entry(void) {
    __asm__ __volatile__(
        /* Swap user SP with sscratch (which holds kernel stack top) */
        "csrrw sp, sscratch, sp\n"
        /* Allocate 31 words on the kernel stack for the trap frame */
        "addi  sp, sp, -4*31\n"
        /* Save all registers except sp (saved last) in the trap_frame layout */
        "sw ra,  4* 0(sp)\n"  /* x1  */
        "sw gp,  4* 1(sp)\n"  /* x3  */
        "sw tp,  4* 2(sp)\n"  /* x4  */
        "sw t0,  4* 3(sp)\n"  /* x5  */
        "sw t1,  4* 4(sp)\n"  /* x6  */
        "sw t2,  4* 5(sp)\n"  /* x7  */
        "sw t3,  4* 6(sp)\n"  /* x28 */
        "sw t4,  4* 7(sp)\n"  /* x29 */
        "sw t5,  4* 8(sp)\n"  /* x30 */
        "sw t6,  4* 9(sp)\n"  /* x31 */
        "sw a0,  4*10(sp)\n"  /* x10 syscall arg0 / return value */
        "sw a1,  4*11(sp)\n"  /* x11 syscall arg1 */
        "sw a2,  4*12(sp)\n"  /* x12 syscall arg2 */
        "sw a3,  4*13(sp)\n"  /* x13 syscall number */
        "sw a4,  4*14(sp)\n"  /* x14 syscall arg4 (kv_put vlen) */
        "sw a5,  4*15(sp)\n"  /* x15 */
        "sw a6,  4*16(sp)\n"  /* x16 */
        "sw a7,  4*17(sp)\n"  /* x17 */
        "sw s0,  4*18(sp)\n"  /* x8  */
        "sw s1,  4*19(sp)\n"  /* x9  */
        "sw s2,  4*20(sp)\n"  /* x18 */
        "sw s3,  4*21(sp)\n"  /* x19 */
        "sw s4,  4*22(sp)\n"  /* x20 */
        "sw s5,  4*23(sp)\n"  /* x21 */
        "sw s6,  4*24(sp)\n"  /* x22 */
        "sw s7,  4*25(sp)\n"  /* x23 */
        "sw s8,  4*26(sp)\n"  /* x24 */
        "sw s9,  4*27(sp)\n"  /* x25 */
        "sw s10, 4*28(sp)\n"  /* x26 */
        "sw s11, 4*29(sp)\n"  /* x27 */
        /* Read original user SP from sscratch and save it as trap_frame.sp */
        "csrr a0, sscratch\n"
        "sw a0,  4*30(sp)\n"  /* x2 = original user SP */
        /* Update sscratch to point just above the trap frame (kernel stack top for next trap) */
        "addi a0, sp, 4*31\n"
        "csrw sscratch, a0\n"
        /* Pass trap frame pointer as first argument to handle_trap */
        "mv a0, sp\n"
        "call handle_trap\n"  /* C handler; returns with registers possibly changed */
        /* Restore all registers from the (possibly modified) trap frame */
        "lw ra,  4* 0(sp)\n"
        "lw gp,  4* 1(sp)\n"
        "lw tp,  4* 2(sp)\n"
        "lw t0,  4* 3(sp)\n"
        "lw t1,  4* 4(sp)\n"
        "lw t2,  4* 5(sp)\n"
        "lw t3,  4* 6(sp)\n"
        "lw t4,  4* 7(sp)\n"
        "lw t5,  4* 8(sp)\n"
        "lw t6,  4* 9(sp)\n"
        "lw a0,  4*10(sp)\n"
        "lw a1,  4*11(sp)\n"
        "lw a2,  4*12(sp)\n"
        "lw a3,  4*13(sp)\n"
        "lw a4,  4*14(sp)\n"
        "lw a5,  4*15(sp)\n"
        "lw a6,  4*16(sp)\n"
        "lw a7,  4*17(sp)\n"
        "lw s0,  4*18(sp)\n"
        "lw s1,  4*19(sp)\n"
        "lw s2,  4*20(sp)\n"
        "lw s3,  4*21(sp)\n"
        "lw s4,  4*22(sp)\n"
        "lw s5,  4*23(sp)\n"
        "lw s6,  4*24(sp)\n"
        "lw s7,  4*25(sp)\n"
        "lw s8,  4*26(sp)\n"
        "lw s9,  4*27(sp)\n"
        "lw s10, 4*28(sp)\n"
        "lw s11, 4*29(sp)\n"
        /* Restore user SP last (destroys our frame pointer) */
        "lw sp,  4*30(sp)\n"
        /* sret: return to user mode with sstatus.SPP=0, sepc as PC */
        "sret\n"
    );
}

/* user_entry — trampoline to launch a new user process for the first time.
 *
 * Called via ret from switch_context (ra was set to user_entry).
 * Sets sepc = USER_BASE (the load address of the service binary) and
 * sstatus.SPIE so interrupts are enabled in user mode.  Then sret.
 */
__attribute__((naked)) void user_entry(void) {
    __asm__ __volatile__(
        /* sepc = USER_BASE: this will be the PC after sret */
        "csrw sepc,    %[sepc]\n"
        /* sstatus: SPIE=1 (enable interrupts on sret), SUM=1 (S can access U pages) */
        "csrw sstatus, %[st]\n"
        "sret\n"   /* jump to sepc in U-mode */
        :: [sepc] "r"(USER_BASE),
           [st]   "r"(SSTATUS_SPIE | SSTATUS_SUM)
    );
}

/* ══════════════════════════════════════════════════════════════════════════
 * CONTEXT SWITCH  (naked — saves/restores callee-saved registers only)
 *
 * Called with:  switch_context(&prev->sp, &next->sp)
 *   a0 = pointer to prev->sp  (we save SP here)
 *   a1 = pointer to next->sp  (we load SP from here)
 *
 * Only ra and s0-s11 need saving; the C ABI guarantees callers save a0-a7/t0-t6.
 * On first run, next->sp was set up by create_process() with ra=user_entry.
 * ══════════════════════════════════════════════════════════════════════════ */
__attribute__((naked)) void switch_context(uint32_t *prev_sp, uint32_t *next_sp) {
    __asm__ __volatile__(
        /* Allocate 13 words for: ra, s0-s11 */
        "addi sp, sp, -13*4\n"
        /* Save callee-saved registers */
        "sw ra,  0*4(sp)\n"   /* return address: first restore target */
        "sw s0,  1*4(sp)\n"
        "sw s1,  2*4(sp)\n"
        "sw s2,  3*4(sp)\n"
        "sw s3,  4*4(sp)\n"
        "sw s4,  5*4(sp)\n"
        "sw s5,  6*4(sp)\n"
        "sw s6,  7*4(sp)\n"
        "sw s7,  8*4(sp)\n"
        "sw s8,  9*4(sp)\n"
        "sw s9, 10*4(sp)\n"
        "sw s10,11*4(sp)\n"
        "sw s11,12*4(sp)\n"
        /* Store current SP into *prev_sp */
        "sw sp, (a0)\n"
        /* Load next process's SP from *next_sp */
        "lw sp, (a1)\n"
        /* Restore callee-saved registers of next process */
        "lw ra,  0*4(sp)\n"
        "lw s0,  1*4(sp)\n"
        "lw s1,  2*4(sp)\n"
        "lw s2,  3*4(sp)\n"
        "lw s3,  4*4(sp)\n"
        "lw s4,  5*4(sp)\n"
        "lw s5,  6*4(sp)\n"
        "lw s6,  7*4(sp)\n"
        "lw s7,  8*4(sp)\n"
        "lw s8,  9*4(sp)\n"
        "lw s9, 10*4(sp)\n"
        "lw s10,11*4(sp)\n"
        "lw s11,12*4(sp)\n"
        /* Deallocate the saved-register frame */
        "addi sp, sp, 13*4\n"
        /* ret: jumps to ra of the next process (user_entry on first run) */
        "ret\n"
    );
}

/* ══════════════════════════════════════════════════════════════════════════
 * COOPERATIVE SCHEDULER
 *
 * yield() implements a simple round-robin over all PROC_RUNNABLE processes.
 * It is called:
 *   - voluntarily by SYS_YIELD
 *   - by do_ipc_call() when blocking the caller
 *   - by SYS_GETCHAR when no character is available
 *
 * If no other runnable process exists, yield() returns to the caller
 * without switching (avoids unnecessary overhead when only monerod runs).
 * ══════════════════════════════════════════════════════════════════════════ */
void yield(void) {
    struct process *next = idle_proc;  /* default: run idle if nothing else runnable */

    /* Search for the next RUNNABLE process after current_proc in round-robin order */
    for (int i = 0; i < PROCS_MAX; i++) {
        /* Wrap around the procs[] array starting just after current_proc */
        struct process *p = &procs[(current_proc->pid + i) % PROCS_MAX];
        if (p->state == PROC_RUNNABLE && p->pid > 0) {
            next = p;  /* found a candidate; take it */
            break;
        }
    }

    /* No context switch needed if we're already the only runnable process */
    if (next == current_proc) return;

    struct process *prev = current_proc;  /* remember who we're switching away from */
    current_proc = next;                  /* update current process pointer */

    /* Switch to next process's page table (SV32: write satp with SV32|PPN) */
    __asm__ __volatile__(
        "sfence.vma\n"                   /* flush TLB before changing address space */
        "csrw satp, %[satp]\n"           /* install new page table root            */
        "sfence.vma\n"                   /* flush TLB after  changing address space */
        "csrw sscratch, %[ss]\n"         /* update sscratch to new process's stack top */
        :: [satp] "r"(SATP_SV32 | ((uint32_t)next->page_table / PAGE_SIZE)),
           [ss]   "r"((uint32_t)&next->stack[sizeof(next->stack)])
    );

    /* Perform the actual register-level context switch */
    switch_context(&prev->sp, &next->sp);
    /* Returns here when prev process is scheduled again */
}

/* ══════════════════════════════════════════════════════════════════════════
 * PROCESS CREATION
 *
 * Allocates a process slot, sets up the initial kernel stack frame so that
 * the first switch_context into this process will ret to user_entry (which
 * then sret's to USER_BASE in U-mode), and builds a per-process SV32 page
 * table that:
 *   - Identity-maps all kernel + RAM (so kernel code runs post-trap)
 *   - Maps the VirtIO MMIO window (needed by the kernel for disk I/O)
 *   - Maps the IPC shared page R/W accessible from both S and U mode
 *   - Maps the service binary at USER_BASE
 * ══════════════════════════════════════════════════════════════════════════ */
struct process *create_process(const void *image, size_t image_size, uint8_t caps) {
    /* Find a free process control block */
    struct process *proc = NULL;
    for (int i = 0; i < PROCS_MAX; i++)
        if (procs[i].state == PROC_UNUSED) { proc = &procs[i]; break; }
    if (!proc) PANIC("no free process slots");

    /* Set up the initial kernel stack frame for switch_context.
     * The frame layout matches what switch_context saves: ra + s0-s11.
     * We push 13 zeros (s11 down to s0), then ra = user_entry.           */
    uint32_t *sp = (uint32_t *)&proc->stack[sizeof(proc->stack)]; /* top of stack */
    for (int i = 0; i < 12; i++) *--sp = 0;     /* s11..s0: zero-initialised     */
    *--sp = (uint32_t)user_entry;                /* ra: first context switch rets here */

    /* Allocate the top-level SV32 page table (one page = 1024 PTEs × 4 bytes) */
    uint32_t *pt = (uint32_t *)alloc_pages(1);

    /* Identity-map the entire kernel and free-RAM region.
     * Services need kernel mappings active during trap handling (S-mode runs
     * with the process's page table, not a separate kernel page table).    */
    for (paddr_t pa = (paddr_t)__kernel_base;
         pa < (paddr_t)__free_ram_end; pa += PAGE_SIZE)
        map_page(pt, pa, pa, PAGE_R | PAGE_W | PAGE_X); /* kernel: RWX (no PAGE_U) */

    /* Map the VirtIO-blk MMIO registers (kernel needs this for disk I/O) */
    map_page(pt, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W);

    /* Allocate and map the IPC shared buffer page (userspace-accessible) */
    paddr_t ipc_pa  = alloc_pages(1);                   /* one page for ipc_msg  */
    proc->ipc_buf   = (struct ipc_msg *)ipc_pa;
    /* PAGE_U: user process can read/write the IPC page directly */
    map_page(pt, ipc_pa, ipc_pa, PAGE_R | PAGE_W | PAGE_U);

    /* Map the service binary at USER_BASE, one page at a time */
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
        paddr_t pg = alloc_pages(1);                     /* fresh physical page      */
        /* Copy up to PAGE_SIZE bytes of the image into this page */
        size_t n = (PAGE_SIZE < image_size - off) ? PAGE_SIZE : (image_size - off);
        memcpy((void *)pg, (const uint8_t *)image + off, n);
        /* Map at USER_BASE + off with user-readable/writable/executable */
        map_page(pt, USER_BASE + off, pg, PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }

    /* Fill in the process control block */
    proc->pid          = (int)(proc - procs) + 1; /* 1-based PID (0 is idle)    */
    proc->state        = PROC_RUNNABLE;            /* ready to run immediately   */
    proc->capabilities = caps;                     /* capability bitmask         */
    proc->sp           = (uint32_t)sp;             /* kernel stack pointer       */
    proc->page_table   = pt;                       /* SV32 root page table       */
    return proc;
}

/* ══════════════════════════════════════════════════════════════════════════
 * CAPABILITY-GATED IPC
 *
 * do_ipc_call implements synchronous message-passing:
 *   1. Check the caller holds the capability required for this message type.
 *   2. Resolve the target service PID from the message type.
 *   3. Write the request into the target's shared ipc_buf.
 *   4. Mark caller BLOCKED, target RUNNABLE, then yield().
 *   5. The target service (running in user mode) dispatches the request,
 *      writes the reply into ipc_buf, and sets ipc_buf->type = 0.
 *   6. When the scheduler re-runs the caller, it resumes here, reads the
 *      reply, and returns the status code.
 *
 * Security property: a caller lacking the required CAP_* bit gets
 * IPC_STATUS_DENIED and the target service is never woken up.
 * ══════════════════════════════════════════════════════════════════════════ */
static int do_ipc_call(uint8_t type,
                        const uint8_t *payload, uint16_t plen,
                        uint8_t *reply,  uint16_t *rlen) {
    int    target_pid;  /* PID of the service to invoke                        */
    uint8_t req_cap;    /* capability bit the caller must hold                 */

    /* Map message type → target service + required capability */
    switch (type) {
        case IPC_CRYPTO_HASH:
        case IPC_CRYPTO_SIGN:
        case IPC_CRYPTO_VERIFY:
            target_pid = pid_crypto;   /* target is crypto_service            */
            req_cap    = CAP_CRYPTO;   /* caller must have CAP_CRYPTO         */
            break;
        case IPC_KV_PUT:
        case IPC_KV_GET:
            target_pid = pid_kv;       /* target is kv_store                  */
            req_cap    = CAP_KVSTORE;  /* caller must have CAP_KVSTORE        */
            break;
        case IPC_NET_BROADCAST:
        case IPC_NET_FETCH_BLOCK:
            target_pid = pid_network;  /* target is network_service           */
            req_cap    = CAP_NETWORK;  /* caller must have CAP_NETWORK        */
            break;
        default:
            return IPC_STATUS_ERROR;   /* unknown message type                */
    }

    /* Capability check: deny if the caller does not hold req_cap */
    if (!(current_proc->capabilities & req_cap)) {
        printf("ipc: pid %d DENIED (need cap 0x%x, has 0x%x, type 0x%x)\n",
               current_proc->pid, req_cap, current_proc->capabilities, type);
        return IPC_STATUS_DENIED;
    }

    /* Validate target PID is in range */
    if (target_pid < 1 || target_pid > PROCS_MAX) {
        printf("ipc: service not registered for type 0x%x\n", type);
        return IPC_STATUS_ERROR;
    }

    struct process *tgt = &procs[target_pid - 1]; /* look up target PCB (PID is 1-based) */
    if (!tgt->ipc_buf) return IPC_STATUS_ERROR;    /* target has no IPC buffer            */

    /* Clamp payload to the buffer limit */
    if (plen > IPC_VALUE_MAX) plen = IPC_VALUE_MAX;

    /* Fill the target's IPC buffer with the request */
    tgt->ipc_buf->type        = type;   /* message type triggers the service's dispatch */
    tgt->ipc_buf->status      = 0;      /* clear previous status                        */
    tgt->ipc_buf->payload_len = plen;   /* how many bytes follow                        */
    if (payload) memcpy(tgt->ipc_buf->payload, payload, plen); /* copy request data     */

    /* Synchronous hand-off: wake target, sleep caller */
    tgt->state          = PROC_RUNNABLE; /* target can now run and see type != 0  */
    current_proc->state = PROC_BLOCKED;  /* caller blocks until reply arrives     */
    yield();                             /* schedule the target                   */

    /* ── Caller resumes here after the target processes the request ── */
    current_proc->state = PROC_RUNNABLE; /* mark ourselves runnable again         */

    /* Copy reply data back to caller if a reply buffer was provided */
    if (reply && rlen) {
        *rlen = tgt->ipc_buf->payload_len;           /* reply byte count             */
        if (*rlen > IPC_VALUE_MAX) *rlen = IPC_VALUE_MAX; /* clamp                  */
        memcpy(reply, tgt->ipc_buf->payload, *rlen); /* copy reply payload           */
    }
    return tgt->ipc_buf->status;  /* return the status code set by the service   */
}

/* ══════════════════════════════════════════════════════════════════════════
 * SYSCALL HANDLER
 *
 * Called from handle_trap when scause == SCAUSE_ECALL.
 * The syscall number is in trap_frame.a3; arguments in a0-a2 (and a4).
 * Return value is written to trap_frame.a0 (a0 is the C ABI return register).
 * ══════════════════════════════════════════════════════════════════════════ */
void handle_syscall(struct trap_frame *f) {
    switch (f->a3) {  /* dispatch on syscall number */

    /* ── SYS_PUTCHAR: write one character to SBI console ── */
    case SYS_PUTCHAR:
        putchar((char)f->a0);   /* a0 = character to emit */
        break;

    /* ── SYS_GETCHAR: blocking read of one character ── */
    case SYS_GETCHAR:
        while (1) {
            long c = getchar();          /* poll SBI console */
            if (c >= 0) { f->a0 = c; break; } /* got a character: return it */
            yield();                     /* nothing available: yield and retry */
        }
        break;

    /* ── SYS_EXIT: terminate the calling process ── */
    case SYS_EXIT:
        printf("kernel: pid %d exited\n", current_proc->pid);
        current_proc->state = PROC_EXITED;  /* mark as done */
        yield();                            /* run another process */
        PANIC("unreachable after SYS_EXIT");

    /* ── SYS_YIELD: voluntarily give up the CPU ── */
    case SYS_YIELD:
        yield();  /* cooperative multitasking: just call the scheduler */
        break;

    /* ── SYS_READFILE / SYS_WRITEFILE: filesystem access ── */
    case SYS_READFILE:
    case SYS_WRITEFILE: {
        const char *name = (const char *)f->a0;  /* a0 = pointer to filename string */
        char       *buf  = (char *)f->a1;         /* a1 = pointer to data buffer     */
        int         len  = f->a2;                 /* a2 = requested byte count       */
        struct file *file = fs_lookup(name);
        if (!file) {
            printf("fs: file not found: %s\n", name);
            f->a0 = -1;                           /* return -1 on error              */
            break;
        }
        /* Clamp len to file size to avoid overreads */
        if (len > file->size) len = file->size;
        if (f->a3 == SYS_WRITEFILE) {
            memcpy(file->data, buf, len);         /* copy caller's data into file    */
            file->size = len;                     /* update file size                */
            fs_flush();                           /* persist to VirtIO disk          */
        } else {
            memcpy(buf, file->data, len);         /* copy file data to caller        */
        }
        f->a0 = len;                              /* return bytes transferred        */
        break;
    }

    /* ── SYS_CRYPTO_HASH: SHA-256 via crypto_service ── */
    case SYS_CRYPTO_HASH: {
        uint8_t *out  = (uint8_t *)f->a2;         /* a2 = output buffer (32 bytes)  */
        uint16_t olen = 0;
        int rc = do_ipc_call(IPC_CRYPTO_HASH,
                              (const uint8_t *)f->a0, (uint16_t)f->a1, /* data, len */
                              out, &olen);
        f->a0 = (rc == IPC_STATUS_OK) ? (int)olen : -rc; /* bytes written or negated error */
        break;
    }

    /* ── SYS_CRYPTO_SIGN: Ed25519 sign via crypto_service ── */
    case SYS_CRYPTO_SIGN: {
        uint8_t *out  = (uint8_t *)f->a2;         /* a2 = output buffer (64 bytes)  */
        uint16_t olen = 0;
        int rc = do_ipc_call(IPC_CRYPTO_SIGN,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              out, &olen);
        f->a0 = (rc == IPC_STATUS_OK) ? (int)olen : -rc;
        break;
    }

    /* ── SYS_KV_PUT: store key→value via kv_store ──
     * Wire format packed into one IPC payload:
     *   [0..1] klen (big-endian uint16)
     *   [2..3] vlen (big-endian uint16)
     *   [4..4+klen) key bytes
     *   [4+klen..4+klen+vlen) value bytes
     */
    case SYS_KV_PUT: {
        uint8_t  buf[IPC_KEY_MAX + IPC_VALUE_MAX + 4]; /* scratch buffer for packed payload */
        uint16_t klen = (uint16_t)f->a1;  /* a1 = key length */
        uint16_t vlen = (uint16_t)f->a4;  /* a4 = value length (extra register) */
        /* Clamp to avoid buffer overflow in the packed payload */
        if (klen > IPC_KEY_MAX)               klen = IPC_KEY_MAX;
        if (vlen > IPC_VALUE_MAX - klen - 4)  vlen = (uint16_t)(IPC_VALUE_MAX - klen - 4);
        /* Pack klen as big-endian uint16 */
        buf[0] = (uint8_t)(klen >> 8);
        buf[1] = (uint8_t)(klen & 0xFF);
        /* Pack vlen as big-endian uint16 */
        buf[2] = (uint8_t)(vlen >> 8);
        buf[3] = (uint8_t)(vlen & 0xFF);
        /* Copy key and value into the packed buffer */
        memcpy(&buf[4],         (const void *)f->a0, klen); /* a0 = key pointer   */
        memcpy(&buf[4 + klen],  (const void *)f->a2, vlen); /* a2 = value pointer */
        f->a0 = do_ipc_call(IPC_KV_PUT, buf, (uint16_t)(4 + klen + vlen), NULL, NULL);
        break;
    }

    /* ── SYS_KV_GET: retrieve value by key via kv_store ──
     * Wire format: [0..1] klen | [2..2+klen) key
     */
    case SYS_KV_GET: {
        uint8_t  buf[IPC_KEY_MAX + 2];     /* packed key payload                  */
        uint16_t klen = (uint16_t)f->a1;   /* a1 = key length                    */
        if (klen > IPC_KEY_MAX) klen = IPC_KEY_MAX;
        buf[0] = (uint8_t)(klen >> 8);     /* big-endian klen high byte          */
        buf[1] = (uint8_t)(klen & 0xFF);   /* big-endian klen low  byte          */
        memcpy(&buf[2], (const void *)f->a0, klen); /* a0 = key pointer           */
        uint8_t reply[IPC_VALUE_MAX];
        uint16_t rlen = 0;
        int rc = do_ipc_call(IPC_KV_GET, buf, (uint16_t)(2 + klen), reply, &rlen);
        if (rc == IPC_STATUS_OK) {
            memcpy((void *)f->a2, reply, rlen); /* a2 = output buffer pointer     */
            f->a0 = (int)rlen;                  /* return number of bytes written */
        } else {
            f->a0 = -rc;                        /* return negated error code      */
        }
        break;
    }

    /* ── SYS_NET_BROADCAST: relay a TX to network peers ── */
    case SYS_NET_BROADCAST: {
        int rc = do_ipc_call(IPC_NET_BROADCAST,
                              (const uint8_t *)f->a0, (uint16_t)f->a1, /* a0=tx, a1=len */
                              NULL, NULL);
        f->a0 = rc;   /* 0 = success */
        break;
    }

    /* ── SYS_NET_FETCH: retrieve a block from network_service ── */
    case SYS_NET_FETCH: {
        uint8_t  blk[IPC_VALUE_MAX]; /* receive buffer for block data             */
        uint16_t blen = 0;
        int rc = do_ipc_call(IPC_NET_FETCH_BLOCK, NULL, 0, blk, &blen);
        if (rc == IPC_STATUS_OK) {
            memcpy((void *)f->a0, blk, blen); /* a0 = destination buffer pointer  */
            f->a0 = (int)blen;                 /* return block byte count          */
        } else {
            f->a0 = -rc;                       /* return negated error code        */
        }
        break;
    }

    default:
        PANIC("unexpected syscall number a3=0x%x pid=%d", f->a3, current_proc->pid);
    }
}

/* handle_trap — called from kernel_entry with the saved trap frame.
 * Only ecall (environment call from U-mode) is expected; everything else
 * is a fatal kernel error. */
void handle_trap(struct trap_frame *f) {
    uint32_t scause = READ_CSR(scause); /* trap cause register                    */
    uint32_t stval  = READ_CSR(stval);  /* trap value (bad address for page faults) */
    uint32_t sepc   = READ_CSR(sepc);   /* program counter at the time of the trap */

    if (scause == SCAUSE_ECALL) {
        handle_syscall(f);      /* dispatch to the correct syscall handler         */
        sepc += 4;              /* advance past the ecall instruction (32-bit)     */
    } else {
        /* Any other trap (page fault, illegal instruction, etc.) is fatal */
        PANIC("unexpected trap scause=0x%x stval=0x%x sepc=0x%x pid=%d",
              scause, stval, sepc, current_proc->pid);
    }
    WRITE_CSR(sepc, sepc);  /* write the (possibly advanced) PC back              */
}

/* ══════════════════════════════════════════════════════════════════════════
 * BOOT SEQUENCE
 * ══════════════════════════════════════════════════════════════════════════ */

/* kernel_main — C entry point called by boot() after stack is valid */
void kernel_main(void) {
    /* Clear the BSS segment (global/static variables that are zero-initialised) */
    memset(__bss, 0, (size_t)__bss_end - (size_t)__bss);

    /* Print the boot banner over SBI console */
    printf("\n");
    printf("==========================================================\n");
    printf("  Protheus OS — RISC-V rv32ima Microkernel\n");
    printf("  Capability-gated IPC | Monocypher Ed25519 | TAR/VirtIO\n");
    printf("==========================================================\n\n");

    /* Install the trap handler vector: all S-mode traps go to kernel_entry */
    WRITE_CSR(stvec, (uint32_t)kernel_entry);

    /* Initialise VirtIO block device (must come before fs_init) */
    virtio_blk_init();

    /* Read service binaries from the TAR disk image into RAM */
    fs_init();

    /* Create the idle process (pid=0).  No image, no capabilities.
     * The idle process is what current_proc points to before any service runs. */
    idle_proc      = create_process(NULL, 0, CAP_NONE);
    idle_proc->pid = 0;        /* override the 1-based PID with 0 for idle       */
    current_proc   = idle_proc;

    /* Service table: binary name on disk → capability bitmask */
    static const struct { const char *name; uint8_t caps; } svcs[] = {
        /* crypto_service: handles Ed25519 and SHA-256; key material lives here */
        { "crypto_service",  CAP_LOG },
        /* kv_store: stores blockchain state; no network access (security boundary) */
        { "kv_store",        CAP_LOG },
        /* network_service: untrusted relay; cannot reach crypto or kv_store */
        { "network_service", CAP_LOG | CAP_TIMER },
        /* monerod: orchestrator; routes all inter-service calls */
        { "monerod",         CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK | CAP_TIMER | CAP_LOG },
        { NULL, 0 }   /* sentinel */
    };

    /* Spawn each service in order and record their PIDs */
    for (int i = 0; svcs[i].name; i++) {
        struct file *f = fs_lookup(svcs[i].name);
        if (!f) {
            printf("kernel: WARNING: '%s' not found on disk — skipping\n", svcs[i].name);
            continue;
        }
        struct process *p = create_process(f->data, f->size, svcs[i].caps);
        printf("kernel: spawned %s  pid=%d  caps=0x%x\n",
               svcs[i].name, p->pid, p->capabilities);
        /* Record service PIDs so do_ipc_call can route messages */
        if (i == 0) pid_crypto  = p->pid;
        if (i == 1) pid_kv      = p->pid;
        if (i == 2) pid_network = p->pid;
    }

    /* Fallback: if monerod binary is missing, start the interactive shell instead */
    if (!fs_lookup("monerod")) {
        create_process(_binary_shell_bin_start,
                       (size_t)_binary_shell_bin_size, CAP_ALL);
        printf("kernel: monerod not found — started fallback shell\n");
    }

    /* Hand control to the scheduler; never returns */
    yield();
    PANIC("idle loop reached — no runnable processes");
}

/* boot — very first instruction executed at reset (address 0x80200000).
 *
 * OpenSBI jumps here in S-mode after setting up M-mode.
 * We just need to set the stack pointer (sp) and jump to kernel_main.
 * Everything else (BSS, devices) is done in kernel_main.
 *
 * The section attribute ensures this lands at the top of .text.
 */
__attribute__((section(".text.boot"))) __attribute__((naked))
void boot(void) {
    __asm__ __volatile__(
        "mv sp, %[top]\n"   /* set stack pointer to top of kernel stack */
        "j kernel_main\n"   /* jump (not call) to kernel_main           */
        :: [top] "r"(__stack_top)
    );
}
