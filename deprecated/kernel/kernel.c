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
 * IPC flow (capability-gated):
 *   user ecall → handle_trap → handle_syscall → do_ipc_call
 *     → target->state = RUNNABLE, caller->state = BLOCKED
 *     → yield() (target runs, writes reply into shared ipc_buf)
 *     → caller resumes, reads reply
 */

#include "kernel.h"
#include "common.h"

/* ── Linker symbols ─────────────────────────────────────────────────────── */
extern char __kernel_base[];
extern char __stack_top[];
extern char __bss[], __bss_end[];
extern char __free_ram[], __free_ram_end[];
extern char _binary_shell_bin_start[], _binary_shell_bin_size[];

/* ── Global state ───────────────────────────────────────────────────────── */
struct process  procs[PROCS_MAX];
struct process *current_proc;
struct process *idle_proc;

static int pid_crypto  = -1;
static int pid_kv      = -1;
static int pid_network = -1;

/* ── Physical memory allocator (bump, zeroed) ───────────────────────────── */

paddr_t alloc_pages(uint32_t n) {
    static paddr_t next = (paddr_t)__free_ram;   /* initialised once */
    paddr_t base = next;
    next += n * PAGE_SIZE;
    if (next > (paddr_t)__free_ram_end)
        PANIC("out of memory");
    memset((void *)base, 0, n * PAGE_SIZE);
    return base;
}

/* ── SV32 page-table management ─────────────────────────────────────────── */

void map_page(uint32_t *table1, uint32_t vaddr, paddr_t paddr, uint32_t flags) {
    if (!is_aligned(vaddr,  PAGE_SIZE)) PANIC("unaligned vaddr %x",  vaddr);
    if (!is_aligned(paddr,  PAGE_SIZE)) PANIC("unaligned paddr %x",  paddr);

    uint32_t vpn1 = (vaddr >> 22) & 0x3ff;
    if (!(table1[vpn1] & PAGE_V)) {
        uint32_t pt = alloc_pages(1);
        table1[vpn1] = ((pt / PAGE_SIZE) << 10) | PAGE_V;
    }
    uint32_t vpn0   = (vaddr >> 12) & 0x3ff;
    uint32_t *table0 = (uint32_t *)((table1[vpn1] >> 10) * PAGE_SIZE);
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

/* ── SBI ────────────────────────────────────────────────────────────────── */

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

/* ── Console ────────────────────────────────────────────────────────────── */

void putchar(char ch) { sbi_call(ch, 0, 0, 0, 0, 0, 0, 1); }

long getchar(void) { return sbi_call(0, 0, 0, 0, 0, 0, 0, 2).error; }

/* ── VirtIO block device ────────────────────────────────────────────────── */

static struct virtio_virtq *blk_request_vq;
static struct virtio_blk_req *blk_req;
static paddr_t blk_req_paddr;
static uint64_t blk_capacity;

static uint32_t vreg32(unsigned off) {
    return *(volatile uint32_t *)(VIRTIO_BLK_PADDR + off);
}
static uint64_t vreg64(unsigned off) {
    return *(volatile uint64_t *)(VIRTIO_BLK_PADDR + off);
}
static void vwreg32(unsigned off, uint32_t v) {
    *(volatile uint32_t *)(VIRTIO_BLK_PADDR + off) = v;
}
static void vor32(unsigned off, uint32_t v) { vwreg32(off, vreg32(off) | v); }

static void virtq_kick(struct virtio_virtq *vq, int desc) {
    vq->avail.ring[vq->avail.index % VIRTQ_ENTRY_NUM] = desc;
    vq->avail.index++;
    __sync_synchronize();
    vwreg32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
    vq->last_used_index++;
}

static struct virtio_virtq *virtq_init(unsigned idx) {
    paddr_t pa = alloc_pages(
        align_up(sizeof(struct virtio_virtq), PAGE_SIZE) / PAGE_SIZE);
    struct virtio_virtq *vq = (struct virtio_virtq *)pa;
    vq->queue_index = idx;
    vq->used_index  = (volatile uint16_t *)&vq->used.index;
    vwreg32(VIRTIO_REG_QUEUE_SEL, idx);
    vwreg32(VIRTIO_REG_QUEUE_NUM, VIRTQ_ENTRY_NUM);
    vwreg32(VIRTIO_REG_QUEUE_PFN, pa / PAGE_SIZE);
    return vq;
}

void virtio_blk_init(void) {
    if (vreg32(VIRTIO_REG_MAGIC)     != 0x74726976) PANIC("virtio: bad magic");
    if (vreg32(VIRTIO_REG_VERSION)   != 1)          PANIC("virtio: bad version");
    if (vreg32(VIRTIO_REG_DEVICE_ID) != VIRTIO_DEVICE_BLK) PANIC("virtio: not blk");

    vwreg32(VIRTIO_REG_DEVICE_STATUS, 0);
    vor32  (VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    vor32  (VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);
    vwreg32(VIRTIO_REG_PAGE_SIZE, PAGE_SIZE);
    blk_request_vq = virtq_init(0);
    vwreg32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

    blk_capacity  = vreg64(VIRTIO_REG_DEVICE_CONFIG) * SECTOR_SIZE;
    blk_req_paddr = alloc_pages(
        align_up(sizeof(*blk_req), PAGE_SIZE) / PAGE_SIZE);
    blk_req = (struct virtio_blk_req *)blk_req_paddr;
    printf("virtio-blk: %u bytes\n", (unsigned)blk_capacity);
}

void read_write_disk(void *buf, unsigned sector, int is_write) {
    if (sector >= blk_capacity / SECTOR_SIZE) {
        printf("virtio: sector %u out of range\n", sector); return;
    }
    blk_req->sector = sector;
    blk_req->type   = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
    if (is_write) memcpy(blk_req->data, buf, SECTOR_SIZE);

    struct virtio_virtq *vq = blk_request_vq;
    vq->descs[0].addr  = blk_req_paddr;
    vq->descs[0].len   = sizeof(uint32_t) * 2 + sizeof(uint64_t);
    vq->descs[0].flags = VIRTQ_DESC_F_NEXT;   vq->descs[0].next = 1;
    vq->descs[1].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, data);
    vq->descs[1].len   = SECTOR_SIZE;
    vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE);
    vq->descs[1].next  = 2;
    vq->descs[2].addr  = blk_req_paddr + offsetof(struct virtio_blk_req, status);
    vq->descs[2].len   = sizeof(uint8_t);
    vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

    virtq_kick(vq, 0);
    while (vq->last_used_index != *vq->used_index) ;

    if (blk_req->status != 0)
        printf("virtio: sector %u I/O error (status=%d)\n",
               sector, blk_req->status);
    if (!is_write) memcpy(buf, blk_req->data, SECTOR_SIZE);
}

/* ── TAR filesystem ─────────────────────────────────────────────────────── */

static struct file files[FILES_MAX];
static uint8_t     disk[DISK_MAX_SIZE];

static int oct2int(char *oct, int len) {
    int v = 0;
    for (int i = 0; i < len; i++) {
        if (oct[i] < '0' || oct[i] > '7') break;
        v = v * 8 + (oct[i] - '0');
    }
    return v;
}

void fs_flush(void) {
    memset(disk, 0, sizeof(disk));
    unsigned off = 0;
    for (int i = 0; i < FILES_MAX; i++) {
        struct file *f = &files[i];
        if (!f->in_use) continue;
        struct tar_header *h = (struct tar_header *)&disk[off];
        memset(h, 0, sizeof(*h));
        strcpy(h->name, f->name);
        strcpy(h->mode, "000644");
        strcpy(h->magic, "ustar");
        strcpy(h->version, "00");
        h->type = '0';
        int sz = f->size;
        for (int j = sizeof(h->size); j > 0; j--) { h->size[j-1]='0'+(sz%8); sz/=8; }
        int ck = ' ' * (int)sizeof(h->checksum);
        for (unsigned j = 0; j < sizeof(struct tar_header); j++)
            ck += (unsigned char)disk[off + j];
        for (int j = 5; j >= 0; j--) { h->checksum[j]='0'+(ck%8); ck/=8; }
        memcpy(h->data, f->data, f->size);
        off += align_up(sizeof(struct tar_header) + f->size, SECTOR_SIZE);
    }
    for (unsigned s = 0; s < sizeof(disk) / SECTOR_SIZE; s++)
        read_write_disk(&disk[s * SECTOR_SIZE], s, true);
    printf("fs: flushed %u bytes\n", (unsigned)sizeof(disk));
}

void fs_init(void) {
    for (unsigned s = 0; s < sizeof(disk) / SECTOR_SIZE; s++)
        read_write_disk(&disk[s * SECTOR_SIZE], s, false);
    unsigned off = 0;
    for (int i = 0; i < FILES_MAX; i++) {
        struct tar_header *h = (struct tar_header *)&disk[off];
        if (h->name[0] == '\0') break;
        if (strcmp(h->magic, "ustar") != 0)
            PANIC("bad tar magic: \"%s\"", h->magic);
        int sz = oct2int(h->size, sizeof(h->size));
        if (sz > FILE_DATA_MAX) sz = FILE_DATA_MAX;
        struct file *f = &files[i];
        f->in_use = true;
        strncpy(f->name, h->name, 99); f->name[99] = '\0';
        memcpy(f->data, h->data, sz);
        f->size = sz;
        printf("fs: '%s' (%d bytes)\n", f->name, f->size);
        off += align_up(sizeof(struct tar_header) + sz, SECTOR_SIZE);
    }
}

struct file *fs_lookup(const char *name) {
    for (int i = 0; i < FILES_MAX; i++)
        if (files[i].in_use && strcmp(files[i].name, name) == 0)
            return &files[i];
    return NULL;
}

/* ── Trap entry / exit ──────────────────────────────────────────────────── */

__attribute__((naked)) __attribute__((aligned(4)))
void kernel_entry(void) {
    __asm__ __volatile__(
        "csrrw sp, sscratch, sp\n"
        "addi  sp, sp, -4*31\n"
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
        "csrr a0, sscratch\n"
        "sw a0,  4*30(sp)\n"
        "addi a0, sp, 4*31\n"
        "csrw sscratch, a0\n"
        "mv a0, sp\n"
        "call handle_trap\n"
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
        "lw sp,  4*30(sp)\n"
        "sret\n"
    );
}

__attribute__((naked)) void user_entry(void) {
    __asm__ __volatile__(
        "csrw sepc,    %[sepc]\n"
        "csrw sstatus, %[st]\n"
        "sret\n"
        :: [sepc] "r"(USER_BASE), [st] "r"(SSTATUS_SPIE | SSTATUS_SUM)
    );
}

/* ── Context switch ─────────────────────────────────────────────────────── */

__attribute__((naked)) void switch_context(uint32_t *prev_sp, uint32_t *next_sp) {
    __asm__ __volatile__(
        "addi sp, sp, -13*4\n"
        "sw ra,  0*4(sp)\n" "sw s0,  1*4(sp)\n" "sw s1,  2*4(sp)\n"
        "sw s2,  3*4(sp)\n" "sw s3,  4*4(sp)\n" "sw s4,  5*4(sp)\n"
        "sw s5,  6*4(sp)\n" "sw s6,  7*4(sp)\n" "sw s7,  8*4(sp)\n"
        "sw s8,  9*4(sp)\n" "sw s9, 10*4(sp)\n" "sw s10,11*4(sp)\n"
        "sw s11,12*4(sp)\n"
        "sw sp, (a0)\n"
        "lw sp, (a1)\n"
        "lw ra,  0*4(sp)\n" "lw s0,  1*4(sp)\n" "lw s1,  2*4(sp)\n"
        "lw s2,  3*4(sp)\n" "lw s3,  4*4(sp)\n" "lw s4,  5*4(sp)\n"
        "lw s5,  6*4(sp)\n" "lw s6,  7*4(sp)\n" "lw s7,  8*4(sp)\n"
        "lw s8,  9*4(sp)\n" "lw s9, 10*4(sp)\n" "lw s10,11*4(sp)\n"
        "lw s11,12*4(sp)\n"
        "addi sp, sp, 13*4\n"
        "ret\n"
    );
}

/* ── Scheduler ──────────────────────────────────────────────────────────── */

void yield(void) {
    struct process *next = idle_proc;
    for (int i = 0; i < PROCS_MAX; i++) {
        struct process *p = &procs[(current_proc->pid + i) % PROCS_MAX];
        if (p->state == PROC_RUNNABLE && p->pid > 0) { next = p; break; }
    }
    if (next == current_proc) return;

    struct process *prev = current_proc;
    current_proc = next;
    __asm__ __volatile__(
        "sfence.vma\n"
        "csrw satp, %[satp]\n"
        "sfence.vma\n"
        "csrw sscratch, %[ss]\n"
        :: [satp] "r"(SATP_SV32 | ((uint32_t)next->page_table / PAGE_SIZE)),
           [ss]   "r"((uint32_t)&next->stack[sizeof(next->stack)])
    );
    switch_context(&prev->sp, &next->sp);
}

/* ── Process creation ───────────────────────────────────────────────────── */

struct process *create_process(const void *image, size_t image_size,
                                uint8_t caps) {
    struct process *proc = NULL;
    for (int i = 0; i < PROCS_MAX; i++)
        if (procs[i].state == PROC_UNUSED) { proc = &procs[i]; break; }
    if (!proc) PANIC("no free process slots");

    uint32_t *sp = (uint32_t *)&proc->stack[sizeof(proc->stack)];
    for (int i = 0; i < 12; i++) *--sp = 0;  /* s11–s0 */
    *--sp = (uint32_t)user_entry;             /* ra */

    uint32_t *pt = (uint32_t *)alloc_pages(1);

    /* Identity-map kernel + free RAM */
    for (paddr_t pa = (paddr_t)__kernel_base;
         pa < (paddr_t)__free_ram_end; pa += PAGE_SIZE)
        map_page(pt, pa, pa, PAGE_R | PAGE_W | PAGE_X);

    /* VirtIO MMIO */
    map_page(pt, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R | PAGE_W);

    /* IPC shared page */
    paddr_t ipc_pa = alloc_pages(1);
    proc->ipc_buf  = (struct ipc_msg *)ipc_pa;
    map_page(pt, ipc_pa, ipc_pa, PAGE_R | PAGE_W | PAGE_U);

    /* User image */
    for (uint32_t off = 0; off < image_size; off += PAGE_SIZE) {
        paddr_t pg = alloc_pages(1);
        size_t   n  = (PAGE_SIZE < image_size - off)
                      ? PAGE_SIZE : image_size - off;
        memcpy((void *)pg, (const uint8_t *)image + off, n);
        map_page(pt, USER_BASE + off, pg, PAGE_U | PAGE_R | PAGE_W | PAGE_X);
    }

    proc->pid          = (int)(proc - procs) + 1;
    proc->state        = PROC_RUNNABLE;
    proc->capabilities = caps;
    proc->sp           = (uint32_t)sp;
    proc->page_table   = pt;
    return proc;
}

/* ── Capability-gated IPC ───────────────────────────────────────────────── */
/*
 * do_ipc_call — kernel mediates all cross-service communication.
 * The caller blocks; target becomes runnable; on return the reply is
 * already in target->ipc_buf and copied back to the caller.
 *
 * IMPORTANT: after yield() returns, current_proc is the original caller
 * again (the scheduler put it back).  We do NOT re-set state here —
 * handle_syscall is responsible for setting it to PROC_RUNNABLE before
 * calling yield so the scheduler can see us again when the target finishes.
 */
static int do_ipc_call(uint8_t type,
                        const uint8_t *payload, uint16_t plen,
                        uint8_t *reply, uint16_t *rlen) {
    int target_pid; uint8_t req_cap;
    switch (type) {
        case IPC_CRYPTO_HASH:
        case IPC_CRYPTO_SIGN:
        case IPC_CRYPTO_VERIFY: target_pid=pid_crypto;  req_cap=CAP_CRYPTO;  break;
        case IPC_KV_PUT:
        case IPC_KV_GET:        target_pid=pid_kv;      req_cap=CAP_KVSTORE; break;
        case IPC_NET_BROADCAST:
        case IPC_NET_FETCH_BLOCK: target_pid=pid_network; req_cap=CAP_NETWORK; break;
        default: return IPC_STATUS_ERROR;
    }

    if (!(current_proc->capabilities & req_cap)) {
        printf("ipc: pid %d denied (cap 0x%x, type 0x%x)\n",
               current_proc->pid, req_cap, type);
        return IPC_STATUS_DENIED;
    }
    if (target_pid < 1 || target_pid > PROCS_MAX) {
        printf("ipc: service not registered (type 0x%x)\n", type);
        return IPC_STATUS_ERROR;
    }

    struct process *tgt = &procs[target_pid - 1];
    if (!tgt->ipc_buf) return IPC_STATUS_ERROR;

    /* Fill request */
    tgt->ipc_buf->type = type;
    tgt->ipc_buf->status = 0;
    if (plen > IPC_VALUE_MAX) plen = IPC_VALUE_MAX;
    tgt->ipc_buf->payload_len = plen;
    if (payload) memcpy(tgt->ipc_buf->payload, payload, plen);

    /* Hand off */
    tgt->state          = PROC_RUNNABLE;
    current_proc->state = PROC_BLOCKED;
    yield();

    /* Caller resumes here after target marks ipc_buf->type = 0 */
    current_proc->state = PROC_RUNNABLE;

    if (reply && rlen) {
        *rlen = tgt->ipc_buf->payload_len;
        if (*rlen > IPC_VALUE_MAX) *rlen = IPC_VALUE_MAX;
        memcpy(reply, tgt->ipc_buf->payload, *rlen);
    }
    return tgt->ipc_buf->status;
}

/* ── Syscall handler ────────────────────────────────────────────────────── */

void handle_syscall(struct trap_frame *f) {
    switch (f->a3) {

    case SYS_PUTCHAR:
        putchar((char)f->a0);
        break;

    case SYS_GETCHAR:
        while (1) { long c = getchar(); if (c >= 0) { f->a0 = c; break; } yield(); }
        break;

    case SYS_EXIT:
        printf("kernel: pid %d exited\n", current_proc->pid);
        current_proc->state = PROC_EXITED;
        yield();
        PANIC("unreachable");

    case SYS_YIELD:
        yield();
        break;

    case SYS_READFILE:
    case SYS_WRITEFILE: {
        const char *name = (const char *)f->a0;
        char       *buf  = (char *)f->a1;
        int         len  = f->a2;
        struct file *file = fs_lookup(name);
        if (!file) { printf("fs: not found: %s\n", name); f->a0 = -1; break; }
        if (len > (int)sizeof(file->data)) len = file->size;
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

    case SYS_CRYPTO_HASH: {
        uint8_t *out = (uint8_t *)f->a2; uint16_t olen = 0;
        int rc = do_ipc_call(IPC_CRYPTO_HASH,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              out, &olen);
        f->a0 = (rc == IPC_STATUS_OK) ? olen : -rc;
        break;
    }

    case SYS_CRYPTO_SIGN: {
        uint8_t *out = (uint8_t *)f->a2; uint16_t olen = 0;
        int rc = do_ipc_call(IPC_CRYPTO_SIGN,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              out, &olen);
        f->a0 = (rc == IPC_STATUS_OK) ? olen : -rc;
        break;
    }

    case SYS_KV_PUT: {
        /* a0=key a1=klen a2=val a4=vlen */
        uint8_t  buf[IPC_KEY_MAX + IPC_VALUE_MAX + 4];
        uint16_t klen = (uint16_t)f->a1;
        uint16_t vlen = (uint16_t)f->a4;
        if (klen > IPC_KEY_MAX)               klen = IPC_KEY_MAX;
        if (vlen > IPC_VALUE_MAX - klen - 4)  vlen = IPC_VALUE_MAX - klen - 4;
        buf[0]=(klen>>8); buf[1]=(klen&0xFF);
        buf[2]=(vlen>>8); buf[3]=(vlen&0xFF);
        memcpy(&buf[4],        (const void *)f->a0, klen);
        memcpy(&buf[4 + klen], (const void *)f->a2, vlen);
        f->a0 = do_ipc_call(IPC_KV_PUT, buf, 4+klen+vlen, NULL, NULL);
        break;
    }

    case SYS_KV_GET: {
        uint8_t  buf[IPC_KEY_MAX + 2];
        uint16_t klen = (uint16_t)f->a1;
        if (klen > IPC_KEY_MAX) klen = IPC_KEY_MAX;
        buf[0]=(klen>>8); buf[1]=(klen&0xFF);
        memcpy(&buf[2], (const void *)f->a0, klen);
        uint8_t reply[IPC_VALUE_MAX]; uint16_t rlen = 0;
        int rc = do_ipc_call(IPC_KV_GET, buf, 2+klen, reply, &rlen);
        if (rc == IPC_STATUS_OK) { memcpy((void *)f->a2, reply, rlen); f->a0 = rlen; }
        else                     { f->a0 = -rc; }
        break;
    }

    case SYS_NET_BROADCAST: {
        int rc = do_ipc_call(IPC_NET_BROADCAST,
                              (const uint8_t *)f->a0, (uint16_t)f->a1,
                              NULL, NULL);
        f->a0 = rc;
        break;
    }

    case SYS_NET_FETCH: {
        uint8_t blk[IPC_VALUE_MAX]; uint16_t blen = 0;
        int rc = do_ipc_call(IPC_NET_FETCH_BLOCK, NULL, 0, blk, &blen);
        if (rc == IPC_STATUS_OK) { memcpy((void *)f->a0, blk, blen); f->a0 = blen; }
        else                     { f->a0 = -rc; }
        break;
    }

    default:
        PANIC("unexpected syscall a3=0x%x", f->a3);
    }
}

void handle_trap(struct trap_frame *f) {
    uint32_t scause = READ_CSR(scause);
    uint32_t stval  = READ_CSR(stval);
    uint32_t sepc   = READ_CSR(sepc);
    if (scause == SCAUSE_ECALL) {
        handle_syscall(f);
        sepc += 4;
    } else {
        PANIC("trap scause=0x%x stval=0x%x sepc=0x%x", scause, stval, sepc);
    }
    WRITE_CSR(sepc, sepc);
}

/* ── Boot ───────────────────────────────────────────────────────────────── */

void kernel_main(void) {
    memset(__bss, 0, (size_t)__bss_end - (size_t)__bss);

    printf("\n");
    printf("==========================================================\n");
    printf("  Protheus OS — Microkernel Blockchain Runtime\n");
    printf("  Author: m26steph@uwaterloo.ca\n");
    printf("  Credits: Nicolae Carabut (Dispatch Labs)\n");
    printf("==========================================================\n\n");

    WRITE_CSR(stvec, (uint32_t)kernel_entry);
    virtio_blk_init();
    fs_init();

    idle_proc      = create_process(NULL, 0, CAP_NONE);
    idle_proc->pid = 0;
    current_proc   = idle_proc;

    struct { const char *name; uint8_t caps; } svcs[] = {
        { "crypto_service",  CAP_LOG },
        { "kv_store",        CAP_LOG },
        { "network_service", CAP_LOG | CAP_TIMER },
        { "monerod",         CAP_CRYPTO | CAP_KVSTORE | CAP_NETWORK | CAP_TIMER | CAP_LOG },
        { NULL, 0 }
    };

    for (int i = 0; svcs[i].name; i++) {
        struct file *f = fs_lookup(svcs[i].name);
        if (!f) { printf("kernel: WARNING: %s not found\n", svcs[i].name); continue; }
        struct process *p = create_process(f->data, f->size, svcs[i].caps);
        printf("kernel: %s pid=%d caps=0x%x\n", svcs[i].name, p->pid, p->capabilities);
        if (i == 0) pid_crypto  = p->pid;
        if (i == 1) pid_kv      = p->pid;
        if (i == 2) pid_network = p->pid;
    }

    /* Fallback: shell if no monerod image */
    if (!fs_lookup("monerod")) {
        create_process(_binary_shell_bin_start,
                       (size_t)_binary_shell_bin_size, CAP_ALL);
        printf("kernel: no monerod — shell started\n");
    }

    yield();
    PANIC("idle reached");
}

__attribute__((section(".text.boot"))) __attribute__((naked))
void boot(void) {
    __asm__ __volatile__(
        "mv sp, %[top]\n"
        "j kernel_main\n"
        :: [top] "r"(__stack_top)
    );
}
