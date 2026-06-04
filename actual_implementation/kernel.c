/*
 * Protheus OS - Kernel
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * Architecture: RISC-V rv32ima, SV32 paging, OpenSBI, VirtIO block
 *
 * Isolation model
 * ───────────────
 *   crypto_service  CAP_LOG only         — private keys, no I/O
 *   kv_store        CAP_LOG              — disk-backed KV, no network
 *   network_service CAP_LOG | CAP_TIMER  — P2P only
 *   monerod         CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK | CAP_TIMER | CAP_LOG
 *
 * IPC flow: monerod issues a syscall → kernel validates capability →
 *           copies ipc_msg into target's ipc_buf → unblocks target →
 *           target processes → kernel copies reply → resumes caller.
 */

#include "kernel.h"
#include "common.h"

/* ── External linker symbols ─────────────────────────────────────────────── */
extern char __kernel_base[];
extern char __stack_top[];
extern char __bss[], __bss_end[];
extern char __free_ram[], __free_ram_end[];
extern char _binary_shell_bin_start[], _binary_shell_bin_size[];

/* ── Global state ────────────────────────────────────────────────────────── */
struct process  procs[PROCS_MAX];
struct process *current_proc;
struct process *idle_proc;

/* Service PID registry – populated during boot */
static int pid_crypto   = -1;
static int pid_kv_store = -1;
static int pid_network  = -1;

/* ── Physical memory allocator ───────────────────────────────────────────── */

paddr_t alloc_pages(uint32_t n) {
    static paddr_t next_paddr = (paddr_t) __free_ram;
    paddr_t paddr = next_paddr;
    next_paddr += n * PAGE_SIZE;
    if (next_paddr > (paddr_t) __free_ram_end)
        PANIC("out of memory");
    memset((void *) paddr, 0, n * PAGE_SIZE);
    return paddr;
}

/* ── SV32 page table management ──────────────────────────────────────────── */

void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
    if (!is_aligned(vaddr, PAGE_SIZE))
        PANIC("unaligned vaddr %x", vaddr);
    if (!is_aligned(paddr, PAGE_SIZE))
        PANIC("unaligned paddr %x", paddr);

    uint32_t vpn1 = (vaddr >> 22) & 0x3ff;
    if ((table1[vpn1] & PAGE_V) == 0) {
        uint32_t pt_paddr = alloc_pages(1);
        table1[vpn1] = ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V;
    }

    uint32_t vpn0 = (vaddr >> 12) & 0x3ff;
    uint32_t *table0 = (uint32_t *) ((table1[vpn1] >> 10) * PAGE_SIZE);
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

/* ── SBI interface ───────────────────────────────────────────────────────── */

struct sbiret sbi_call(long a0, long a1, long a2, long a3, long a4,
                       long a5, long fid, long eid) {
    register long _a0 __asm__("a0") = a0;
    register long _a1 __asm__("a1") = a1;
    register long _a2 __asm__("a2") = a2;
    register long _a3 __asm__("a3") = a3;
    register long _a4 __asm__("a4") = a4;
    register long _a5 __asm__("a5") = a5;
    register long _a6 __asm__("a6") = fid;
    register long _a7 __asm__("a7") = eid;
    __asm__ __volatile__("ecall"
                         : "=r"(_a0), "=r"(_a1)
                         : "r"(_a0), "r"(_a1), "r"(_a2), "r"(_a3),
                           "r"(_a4), "r"(_a5), "r"(_a6), "r"(_a7)
                         : "memory");
    return (struct sbiret){ .error = _a0, .value = _a1 };
}

/* ── Console ─────────────────────────────────────────────────────────────── */

void putchar(char ch) {
    sbi_call(ch, 0, 0, 0, 0, 0, 0, 1 /* Console Putchar */);
}

long getchar(void) {
    struct sbiret ret = sbi_call(0, 0, 0, 0, 0, 0, 0, 2);
    return ret.error;
}

/* ── VirtIO block device ─────────────────────────────────────────────────── */

struct virtio_virtq *blk_request_vq;
struct virtio_blk_req *blk_req;
paddr_t blk_req_paddr;
uint64_t blk_capacity;

static uint32_t virtio_reg_read32(unsigned offset) {
    return *((volatile uint32_t *)(VIRTIO_BLK_PADDR + offset));
}
static uint64_t virtio_reg_read64(unsigned offset) {
    return *((volatile uint64_t *)(VIRTIO_BLK_PADDR + offset));
}
static void virtio_reg_write32(unsigned offset, uint32_t value) {
    *((volatile uint32_t *)(VIRTIO_BLK_PADDR + offset)) = value;
}
static void virtio_reg_fetch_and_or32(unsigned offset, uint32_t value) {
    virtio_reg_write32(offset, virtio_reg_read32(offset) | value);
}

static bool virtq_is_busy(struct virtio_virtq *vq) {
    return vq->last_used_index != *vq->used_index;
}

static void virtq_kick(struct virtio_virtq *vq, int desc_index) {
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc_index;
    vq->avail.index++;
    __sync_synchronize();
    virtio_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    vq->last_used_index++;
}

static struct virtio_virtq *virtq_init(unsigned index) {
    paddr_t virtq_paddr = alloc_pages(
        align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *) virtq_paddr;
    vq->queue_index = index;
    vq->used_index  = (volatile uint16_t *) &vq->used.index;
    virtio_reg_write32(VIRTIO_REG_QUEUE_SEL, index);
    virtio_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);
    virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, virtq_paddr / PAGE_SIZE);
    return vq;
}

void virtio_blk_init(void) {
    if (virtio_reg_read32(VIRTIO_REG_MAGIC) != 0x74726976)
        PANIC("virtio: invalid magic");
    if (virtio_reg_read32(VIRTIO_REG_VERSION) != 1)
        PANIC("virtio: unsupported version");
    if (virtio_reg_read32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK)
        PANIC("virtio: not a block device");

    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0);
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    virtio_reg_fetch_and_or32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    virtio_reg_write32(VIRTIO_REG_PAGE_SIZE, PAGE_SIZE);
    blk_request_vq = virtq_init(0);
    virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

    blk_capacity = virtio_reg_read64(VIRTIO_REG_DEVICE_CONFIG + 0) * SECTOR_SIZE;
    printf("virtio-blk: capacity %u bytes\n", (unsigned) blk_capacity);

    blk_req_paddr = alloc_pages(
        align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
    blk_req = (struct virtio_blk_req *) blk_req_paddr;
}

void read_write_disk(void *buf, unsigned sector, int is_write) {
    if (sector >= blk_capacity / SECTOR_SIZE) {
        printf("virtio: sector %u out of range\n", sector);
        return;
    }
    blk_req->sector = sector;
    blk_req->type   = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    if (is_write)
        memcpy(blk_req->data, buf, SECTOR_SIZE);

    struct virtio_virtq *vq = blk_request_vq;
    vq->descs[0].addr  = blk_req_paddr;
    vq->descs[0].len   = sizeof(uint32_t) * 2 + sizeof(uint64_t);
    vq->descs[0].flags = VIRTQ_DESC_F_NEXT;
    vq->descs[0].next  = 1;

    vq->descs[1].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    vq->descs[1].len   = SECTOR_SIZE;
    vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    vq->descs[1].next  = 2;

    vq->descs[2].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    vq->descs[2].len   = sizeof(uint8_t);
    vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

    virtq_kick(vq, 0);
    while (virtq_is_busy(vq))
        ;

    if (blk_req->status != 0)
        printf("virtio: sector %u I/O error (status=%d)\n",
               sector, blk_req->status);
    if (!is_write)
        memcpy(buf, blk_req->data, SECTOR_SIZE);
}

/* ── TAR filesystem ──────────────────────────────────────────────────────── */

struct file files[FILES_MAX];
uint8_t     disk[DISK_MAX_SIZE];

static int oct2int(char *oct, int len) {
    int dec = 0;
    for (int i = 0; i < len; i++) {
        if (oct[i] < '0' || oct[i] > '7')
            break;
        dec = dec * 8 + (oct[i] - '0');
    }
    return dec;
}

void fs_flush(void) {
    memset(disk, 0, sizeof(disk));
    unsigned off = 0;
    for (int i = 0; i < FILES_MAX; i++) {
        struct file *f = &files[i];
        if (!f->in_use)
            continue;
        struct tar_header *hdr = (struct tar_header *) &disk[off];
        memset(hdr, 0, sizeof(*hdr));
        strcpy(hdr->name, f->name);
        strcpy(hdr->mode, "000644");
        strcpy(hdr->magic, "ustar");
        strcpy(hdr->version, "00");
        hdr->type = '0';

        int filesz = f->size;
        for (int j = sizeof(hdr->size); j > 0; j--) {
            hdr->size[j - 1] = (filesz % 8) + '0';
            filesz /= 8;
        }
        int checksum = ' ' * sizeof(hdr->checksum);
        for (unsigned j = 0; j < sizeof(struct tar_header); j++)
            checksum += (unsigned char) disk[off + j];
        for (int j = 5; j >= 0; j--) {
            hdr->checksum[j] = (checksum % 8) + '0';
            checksum /= 8;
        }
        memcpy(hdr->data, f->data, f->size);
        off += align_up(sizeof(struct tar_header) + f->size, SECTOR_SIZE);
    }
    for (unsigned sector = 0; sector < sizeof(disk) / SECTOR_SIZE; sector++)
        read_write_disk(&disk[sector * SECTOR_SIZE], sector, true);
    printf("fs: flushed %u bytes to disk\n", (unsigned) sizeof(disk));
}

void fs_init(void) {
    for (unsigned sector = 0; sector < sizeof(disk) / SECTOR_SIZE; sector++)
        read_write_disk(&disk[sector * SECTOR_SIZE], sector, false);
    unsigned off = 0;
    for (int i = 0; i < FILES_MAX; i++) {
        struct tar_header *hdr = (struct tar_header *) &disk[off];
        if (hdr->name[0] == '\0')
            break;
        if (strcmp(hdr->magic, "ustar") != 0)
            PANIC("invalid tar magic: \"%s\"", hdr->magic);
        int filesz = oct2int(hdr->size, sizeof(hdr->size));
        struct file *f = &files[i];
        f->in_use = true;
        strcpy(f->name, hdr->name);
        if (filesz > FILE_DATA_MAX) filesz = FILE_DATA_MAX;
        memcpy(f->data, hdr->data, filesz);
        f->size = filesz;
        printf("fs: loaded '%s' (%d bytes)\n", f->name, f->size);
        off += align_up(sizeof(struct tar_header) + filesz, SECTOR_SIZE);
    }
}

struct file *fs_lookup(const char *filename) {
    for (int i = 0; i < FILES_MAX; i++) {
        if (files[i].in_use && strcmp(files[i].name, filename) == 0)
            return &files[i];
    }
    return NULL;
}

/* ── Trap entry / exit ───────────────────────────────────────────────────── */

__attribute__((naked))
__attribute__((aligned(4)))
void kernel_entry(void) {
    __asm__ __volatile__(
        "csrrw sp, sscratch, sp\n"
        "addi sp, sp, -4 * 31\n"
        "sw ra,  4 *  0(sp)\n" "sw gp,  4 *  1(sp)\n" "sw tp,  4 *  2(sp)\n"
        "sw t0,  4 *  3(sp)\n" "sw t1,  4 *  4(sp)\n" "sw t2,  4 *  5(sp)\n"
        "sw t3,  4 *  6(sp)\n" "sw t4,  4 *  7(sp)\n" "sw t5,  4 *  8(sp)\n"
        "sw t6,  4 *  9(sp)\n"
        "sw a0,  4 * 10(sp)\n" "sw a1,  4 * 11(sp)\n" "sw a2,  4 * 12(sp)\n"
        "sw a3,  4 * 13(sp)\n" "sw a4,  4 * 14(sp)\n" "sw a5,  4 * 15(sp)\n"
        "sw a6,  4 * 16(sp)\n" "sw a7,  4 * 17(sp)\n"
        "sw s0,  4 * 18(sp)\n" "sw s1,  4 * 19(sp)\n" "sw s2,  4 * 20(sp)\n"
        "sw s3,  4 * 21(sp)\n" "sw s4,  4 * 22(sp)\n" "sw s5,  4 * 23(sp)\n"
        "sw s6,  4 * 24(sp)\n" "sw s7,  4 * 25(sp)\n" "sw s8,  4 * 26(sp)\n"
        "sw s9,  4 * 27(sp)\n" "sw s10, 4 * 28(sp)\n" "sw s11, 4 * 29(sp)\n"
        "csrr a0, sscratch\n"
        "sw a0,  4 * 30(sp)\n"
        "addi a0, sp, 4 * 31\n"
        "csrw sscratch, a0\n"
        "mv a0, sp\n"
        "call handle_trap\n"
        "lw ra,  4 *  0(sp)\n" "lw gp,  4 *  1(sp)\n" "lw tp,  4 *  2(sp)\n"
        "lw t0,  4 *  3(sp)\n" "lw t1,  4 *  4(sp)\n" "lw t2,  4 *  5(sp)\n"
        "lw t3,  4 *  6(sp)\n" "lw t4,  4 *  7(sp)\n" "lw t5,  4 *  8(sp)\n"
        "lw t6,  4 *  9(sp)\n"
        "lw a0,  4 * 10(sp)\n" "lw a1,  4 * 11(sp)\n" "lw a2,  4 * 12(sp)\n"
        "lw a3,  4 * 13(sp)\n" "lw a4,  4 * 14(sp)\n" "lw a5,  4 * 15(sp)\n"
        "lw a6,  4 * 16(sp)\n" "lw a7,  4 * 17(sp)\n"
        "lw s0,  4 * 18(sp)\n" "lw s1,  4 * 19(sp)\n" "lw s2,  4 * 20(sp)\n"
        "lw s3,  4 * 21(sp)\n" "lw s4,  4 * 22(sp)\n" "lw s5,  4 * 23(sp)\n"
        "lw s6,  4 * 24(sp)\n" "lw s7,  4 * 25(sp)\n" "lw s8,  4 * 26(sp)\n"
        "lw s9,  4 * 27(sp)\n" "lw s10, 4 * 28(sp)\n" "lw s11, 4 * 29(sp)\n"
        "lw sp,  4 * 30(sp)\n"
        "sret\n"
    );
}

__attribute__((naked)) void user_entry(void) {
    __asm__ __volatile__(
        "csrw sepc, %[sepc]\n"
        "csrw sstatus, %[sstatus]\n"
        "sret\n"
        :
        : [sepc]    "r"(USER_BASE),
          [sstatus] "r"(SSTATUS_SPIE | SSTATUS_SUM)
    );
}

/* ── Context switch ──────────────────────────────────────────────────────── */

__attribute__((naked)) void switch_context(uint32_t *prev_sp, uint32_t *next_sp) {
    __asm__ __volatile__(
        "addi sp, sp, -13 * 4\n"
        "sw ra,  0  * 4(sp)\n" "sw s0,  1  * 4(sp)\n" "sw s1,  2  * 4(sp)\n"
        "sw s2,  3  * 4(sp)\n" "sw s3,  4  * 4(sp)\n" "sw s4,  5  * 4(sp)\n"
        "sw s5,  6  * 4(sp)\n" "sw s6,  7  * 4(sp)\n" "sw s7,  8  * 4(sp)\n"
        "sw s8,  9  * 4(sp)\n" "sw s9,  10 * 4(sp)\n" "sw s10, 11 * 4(sp)\n"
        "sw s11, 12 * 4(sp)\n"
        "sw sp, (a0)\n"
        "lw sp, (a1)\n"
        "lw ra,  0  * 4(sp)\n" "lw s0,  1  * 4(sp)\n" "lw s1,  2  * 4(sp)\n"
        "lw s2,  3  * 4(sp)\n" "lw s3,  4  * 4(sp)\n" "lw s4,  5  * 4(sp)\n"
        "lw s5,  6  * 4(sp)\n" "lw s6,  7  * 4(sp)\n" "lw s7,  8  * 4(sp)\n"
        "lw s8,  9  * 4(sp)\n" "lw s9,  10 * 4(sp)\n" "lw s10, 11 * 4(sp)\n"
        "lw s11, 12 * 4(sp)\n"
        "addi sp, sp, 13 * 4\n"
        "ret\n"
    );
}

/* ── Scheduler ───────────────────────────────────────────────────────────── */

void yield(void) {
    struct process *next = idle_proc;
    for (int i = 0; i < PROCS_MAX; i++) {
        struct process *proc = &procs[(current_proc->pid + i) % PROCS_MAX];
        if (proc->state == PROC_RUNNABLE && proc->pid > 0) {
            next = proc;
            break;
        }
    }
    if (next == current_proc)
        return;

    struct process *prev = current_proc;
    current_proc = next;

    __asm__ __volatile__(
        "sfence.vma\n"
        "csrw satp, %[satp]\n"
        "sfence.vma\n"
        "csrw sscratch, %[sscratch]\n"
        :
        : [satp]    "r"(SATP_SV32 | ((uint32_t) next->page_table / PAGE_SIZE)),
          [sscratch] "r"((uint32_t) &next->stack[sizeof(next->stack)])
    );
    switch_context(&prev->sp, &next->sp);
}

/* ── Process creation ────────────────────────────────────────────────────── */

struct process *create_process(const void *image, size_t image_size,
                                uint8_t capabilities) {
    struct process *proc = NULL;
    for (int i = 0; i < PROCS_MAX; i++) {
        if (procs[i].state == PROC_UNUSED) {
            proc = &procs[i];
            break;
        }
    }
    if (!proc)
        PANIC("no free process slots");

    /* Set up kernel stack (callee-saved regs + ra = user_entry) */
    uint32_t *sp = (uint32_t *) &proc->stack[sizeof(proc->stack)];
    *--sp = 0;                      /* s11 */
    *--sp = 0;                      /* s10 */
    *--sp = 0;                      /* s9  */
    *--sp = 0;                      /* s8  */
    *--sp = 0;                      /* s7  */
    *--sp = 0;                      /* s6  */
    *--sp = 0;                      /* s5  */
    *--sp = 0;                      /* s4  */
    *--sp = 0;                      /* s3  */
    *--sp = 0;                      /* s2  */
    *--sp = 0;                      /* s1  */
    *--sp = 0;                      /* s0  */
    *--sp = (uint32_t) user_entry;  /* ra  */

    /* Build page table */
    uint32_t *page_table = (uint32_t *) alloc_pages(1);

    /* Identity-map kernel pages (R/W/X) */
    for (paddr_t pa = (paddr_t) __kernel_base;
         pa < (paddr_t) __free_ram_end; pa += PAGE_SIZE)
        map_page(page_table, pa, pa, PAGE_R | PAGE_W | PAGE_X);

    /* Map VirtIO MMIO */
    map_page(page_table, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W);

    /* Map IPC shared page (kernel-allocated, user-readable) */
    paddr_t ipc_paddr = alloc_pages(1);
    proc->ipc_buf = (struct ipc_msg *) ipc_paddr;
    map_page(page_table, ipc_paddr, ipc_paddr, PAGE_R | PAGE_W | PAGE_U);

    /* Copy user image */
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
        paddr_t page = alloc_pages(1);
        size_t remaining  = image_size - off;
        size_t copy_size  = (PAGE_SIZE <= remaining) ? PAGE_SIZE : remaining;
        memcpy((void *) page, (const uint8_t *) image + off, copy_size);
        map_page(page_table, USER_BASE + off, page,
                 PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }

    proc->pid          = (int)(proc - procs) + 1;
    proc->state        = PROC_RUNNABLE;
    proc->capabilities = capabilities;
    proc->sp           = (uint32_t) sp;
    proc->page_table   = page_table;
    return proc;
}

/* ── Capability-gated IPC ────────────────────────────────────────────────── */
/*
 * do_ipc_call: caller sends an ipc_msg to the target service process.
 *
 * Security guarantee: the kernel checks `current_proc->capabilities`
 * before performing any copy.  A network_service process cannot issue
 * IPC_CRYPTO_HASH because it lacks CAP_CRYPTO.  This is the hardware-
 * enforced isolation boundary described in the architecture document.
 */

static int do_ipc_call(uint8_t ipc_type, const uint8_t *payload,
                        uint16_t payload_len, uint8_t *reply_out,
                        uint16_t *reply_len_out) {
    /* Resolve target and required capability */
    int target_pid;
    uint8_t required_cap;

    switch (ipc_type) {
        case IPC_CRYPTO_HASH:
        case IPC_CRYPTO_SIGN:
        case IPC_CRYPTO_VERIFY:
            target_pid   = pid_crypto;
            required_cap = CAP_CRYPTO;
            break;
        case IPC_KV_PUT:
        case IPC_KV_GET:
            target_pid   = pid_kv_store;
            required_cap = CAP_KVSTORE;
            break;
        case IPC_NET_BROADCAST:
        case IPC_NET_FETCH_BLOCK:
            target_pid   = pid_network;
            required_cap = CAP_NETWORK;
            break;
        default:
            return IPC_STATUS_ERROR;
    }

    /* Capability check */
    if (!(current_proc->capabilities & required_cap)) {
        printf("ipc: pid %d denied (no cap 0x%x for type 0x%x)\n",
               current_proc->pid, required_cap, ipc_type);
        return IPC_STATUS_DENIED;
    }

    if (target_pid < 0 || target_pid >= PROCS_MAX) {
        printf("ipc: service not registered (type 0x%x)\n", ipc_type);
        return IPC_STATUS_ERROR;
    }

    struct process *target = &procs[target_pid - 1];
    if (!target->ipc_buf) {
        printf("ipc: target pid %d has no ipc_buf\n", target_pid);
        return IPC_STATUS_ERROR;
    }

    /* Fill request */
    target->ipc_buf->type        = ipc_type;
    target->ipc_buf->status      = 0;
    if (payload_len > IPC_VALUE_MAX) payload_len = IPC_VALUE_MAX;
    target->ipc_buf->payload_len = payload_len;
    memcpy(target->ipc_buf->payload, payload, payload_len);

    /* Unblock target, block self */
    target->state       = PROC_RUNNABLE;
    current_proc->state = PROC_BLOCKED;
    yield();

    /* On return, the target has written a response into the shared buffer.
     * Copy reply back to caller. */
    if (reply_out && reply_len_out) {
        *reply_len_out = target->ipc_buf->payload_len;
        memcpy(reply_out, target->ipc_buf->payload, *reply_len_out);
    }
    current_proc->state = PROC_RUNNABLE;
    return target->ipc_buf->status;
}

/* ── Syscall handler ─────────────────────────────────────────────────────── */

void handle_syscall(struct trap_frame *f) {
    switch (f->a3) {
        /* ── Basic I/O ──────────────────────────────────────────────── */
        case SYS_PUTCHAR:
            putchar((char) f->a0);
            break;

        case SYS_GETCHAR:
            while (1) {
                long ch = getchar();
                if (ch >= 0) { f->a0 = ch; break; }
                yield();
            }
            break;

        case SYS_EXIT:
            printf("kernel: pid %d exited\n", current_proc->pid);
            current_proc->state = PROC_EXITED;
            yield();
            PANIC("unreachable");

        case SYS_YIELD:
            yield();
            break;

        /* ── File I/O ───────────────────────────────────────────────── */
        case SYS_READFILE:
        case SYS_WRITEFILE: {
            const char *filename = (const char *) f->a0;
            char       *buf      = (char *) f->a1;
            int         len      = f->a2;
            struct file *file    = fs_lookup(filename);
            if (!file) {
                printf("fs: file not found: %s\n", filename);
                f->a0 = -1;
                break;
            }
            if (len > (int) sizeof(file->data))
                len = file->size;
            if (f->a3 == SYS_WRITEFILE) {
                memcpy(file->data, buf, len);
                file->size = len;
                fs_flush();
            } else {
                memcpy(buf, file->data, len);
            }
            f->a0 = len;
            break;
        }

        /* ── Capability-gated IPC syscalls ──────────────────────────── */
        case SYS_CRYPTO_HASH: {
            const uint8_t *input   = (const uint8_t *) f->a0;
            uint16_t       in_len  = (uint16_t) f->a1;
            uint8_t       *output  = (uint8_t *) f->a2;
            uint16_t       out_len = 0;
            int rc = do_ipc_call(IPC_CRYPTO_HASH, input, in_len,
                                  output, &out_len);
            f->a0 = (rc == IPC_STATUS_OK) ? (int) out_len : -rc;
            break;
        }

        case SYS_CRYPTO_SIGN: {
            const uint8_t *payload = (const uint8_t *) f->a0;
            uint16_t       pay_len = (uint16_t) f->a1;
            uint8_t       *sig_out = (uint8_t *) f->a2;
            uint16_t       sig_len = 0;
            int rc = do_ipc_call(IPC_CRYPTO_SIGN, payload, pay_len,
                                  sig_out, &sig_len);
            f->a0 = (rc == IPC_STATUS_OK) ? (int) sig_len : -rc;
            break;
        }

        case SYS_KV_PUT: {
            /* a0=key_ptr, a1=key_len, a2=val_ptr, a4=val_len */
            uint8_t buf[IPC_KEY_MAX + IPC_VALUE_MAX + 4];
            uint16_t klen = (uint16_t) f->a1;
            uint16_t vlen = (uint16_t) f->a4;
            if (klen > IPC_KEY_MAX) klen = IPC_KEY_MAX;
            if (vlen > IPC_VALUE_MAX - klen - 4) vlen = IPC_VALUE_MAX - klen - 4;
            buf[0] = (uint8_t)(klen >> 8);
            buf[1] = (uint8_t)(klen);
            buf[2] = (uint8_t)(vlen >> 8);
            buf[3] = (uint8_t)(vlen);
            memcpy(&buf[4],        (const void *) f->a0, klen);
            memcpy(&buf[4 + klen], (const void *) f->a2, vlen);
            int rc = do_ipc_call(IPC_KV_PUT, buf, 4 + klen + vlen, NULL, NULL);
            f->a0 = rc;
            break;
        }

        case SYS_KV_GET: {
            uint8_t buf[IPC_KEY_MAX + 2];
            uint16_t klen = (uint16_t) f->a1;
            if (klen > IPC_KEY_MAX) klen = IPC_KEY_MAX;
            buf[0] = (uint8_t)(klen >> 8);
            buf[1] = (uint8_t)(klen);
            memcpy(&buf[2], (const void *) f->a0, klen);
            uint8_t reply[IPC_VALUE_MAX];
            uint16_t reply_len = 0;
            int rc = do_ipc_call(IPC_KV_GET, buf, 2 + klen, reply, &reply_len);
            if (rc == IPC_STATUS_OK) {
                memcpy((void *) f->a2, reply, reply_len);
                f->a0 = reply_len;
            } else {
                f->a0 = -rc;
            }
            break;
        }

        case SYS_NET_BROADCAST: {
            const uint8_t *tx_data = (const uint8_t *) f->a0;
            uint16_t tx_len = (uint16_t) f->a1;
            int rc = do_ipc_call(IPC_NET_BROADCAST, tx_data, tx_len, NULL, NULL);
            f->a0 = rc;
            break;
        }

        case SYS_NET_FETCH: {
            uint8_t block_buf[IPC_VALUE_MAX];
            uint16_t block_len = 0;
            int rc = do_ipc_call(IPC_NET_FETCH_BLOCK, NULL, 0,
                                  block_buf, &block_len);
            if (rc == IPC_STATUS_OK) {
                memcpy((void *) f->a0, block_buf, block_len);
                f->a0 = block_len;
            } else {
                f->a0 = -rc;
            }
            break;
        }

        default:
            PANIC("unexpected syscall a3=0x%x", f->a3);
    }
}

void handle_trap(struct trap_frame *f) {
    uint32_t scause   = READ_CSR(scause);
    uint32_t stval    = READ_CSR(stval);
    uint32_t user_pc  = READ_CSR(sepc);

    if (scause == SCAUSE_ECALL) {
        handle_syscall(f);
        user_pc += 4;  /* skip ecall instruction */
    } else {
        PANIC("unexpected trap scause=0x%x stval=0x%x sepc=0x%x",
              scause, stval, user_pc);
    }
    WRITE_CSR(sepc, user_pc);
}

/* ── Boot ────────────────────────────────────────────────────────────────── */

void kernel_main(void) {
    memset(__bss, 0, (size_t)__bss_end - (size_t)__bss);
    printf("\n");
    printf("=======================================================\n");
    printf("  Protheus OS - Microkernel Blockchain Runtime\n");
    printf("  Author: m26steph@uwaterloo.ca\n");
    printf("  Credits: Nicolae Carabut (Dispatch Labs)\n");
    printf("=======================================================\n\n");

    WRITE_CSR(stvec, (uint32_t) kernel_entry);

    printf("kernel: initializing VirtIO block device...\n");
    virtio_blk_init();

    printf("kernel: mounting TAR filesystem...\n");
    fs_init();

    /* Idle process (pid=0, no capabilities) */
    idle_proc = create_process(NULL, 0, CAP_NONE);
    idle_proc->pid = 0;
    current_proc   = idle_proc;

    /* Service processes – launched from filesystem images embedded in the
     * disk.  Each process gets only the capabilities it strictly needs.
     *
     * crypto_service : CAP_LOG only (no network, no storage writes)
     * kv_store       : CAP_LOG      (disk-backed, isolated from network)
     * network_service: CAP_LOG | CAP_TIMER
     * monerod        : CAP_ALL except raw hardware
     */
    struct file *f_crypto = fs_lookup("crypto_service");
    if (f_crypto) {
        struct process *p = create_process(f_crypto->data, f_crypto->size,
                                           CAP_LOG);
        pid_crypto = p->pid;
        printf("kernel: crypto_service spawned (pid=%d, caps=0x%x)\n",
               p->pid, p->capabilities);
    } else {
        printf("kernel: WARNING: crypto_service image not found\n");
    }

    struct file *f_kv = fs_lookup("kv_store");
    if (f_kv) {
        struct process *p = create_process(f_kv->data, f_kv->size, CAP_LOG);
        pid_kv_store = p->pid;
        printf("kernel: kv_store spawned (pid=%d, caps=0x%x)\n",
               p->pid, p->capabilities);
    } else {
        printf("kernel: WARNING: kv_store image not found\n");
    }

    struct file *f_net = fs_lookup("network_service");
    if (f_net) {
        struct process *p = create_process(f_net->data, f_net->size,
                                           CAP_LOG | CAP_TIMER);
        pid_network = p->pid;
        printf("kernel: network_service spawned (pid=%d, caps=0x%x)\n",
               p->pid, p->capabilities);
    } else {
        printf("kernel: WARNING: network_service image not found\n");
    }

    struct file *f_mono = fs_lookup("monerod");
    if (f_mono) {
        struct process *p = create_process(
            f_mono->data, f_mono->size,
            CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK | CAP_TIMER | CAP_LOG);
        printf("kernel: monerod spawned (pid=%d, caps=0x%x)\n",
               p->pid, p->capabilities);
    } else {
        /* Fall back to built-in shell for development */
        create_process(_binary_shell_bin_start,
                       (size_t) _binary_shell_bin_size, CAP_ALL);
        printf("kernel: no monerod image; shell started\n");
    }

    yield();
    PANIC("switched to idle process");
}

__attribute__((section(".text.boot")))
__attribute__((naked))
void boot(void) {
    __asm__ __volatile__(
        "mv sp, %[stack_top]\n"
        "j kernel_main\n"
        :
        : [stack_top] "r"(__stack_top)
    );
}
