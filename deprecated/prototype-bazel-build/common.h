/*
 * Protheus OS — Common Types & Utilities
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * Target: RISC-V rv32ima, OpenSBI, QEMU virt.
 * Fully freestanding — no host libc.
 *
 * CHANGES vs original:
 *   - Added IPC_NOTIFY syscall number (event-driven wakeup)
 *   - Added SYS_TRNG for hardware entropy harvesting
 *   - Added MMIO_READ32 / MMIO_WRITE32 macros for device register access
 *   - Added barrier macros for memory ordering around MMIO
 *   - Every line annotated with its intent
 */
#pragma once

/* ── Primitive types ───────────────────────────────────────────────────── */
/* Map C99-style fixed-width names to compiler intrinsic sizes for rv32ima. */
typedef int                bool;       /* 32-bit Boolean (0=false, 1=true) */
typedef unsigned char      uint8_t;    /* 8-bit  unsigned byte              */
typedef unsigned short     uint16_t;   /* 16-bit unsigned halfword          */
typedef unsigned int       uint32_t;   /* 32-bit unsigned word (rv32 native) */
typedef unsigned long long uint64_t;   /* 64-bit unsigned dword (soft-emu'd) */
typedef uint32_t           size_t;     /* byte-count type, same width as ptr  */
typedef uint32_t           uintptr_t;  /* integer large enough to hold a ptr  */
typedef uint32_t           paddr_t;    /* physical address (SV32 = 34-bit but
                                          stored as 32-bit page-frame numbers) */
typedef uint32_t           vaddr_t;    /* virtual address (32-bit in SV32)    */

/* Standard Boolean constants */
#define true  1   /* Boolean true  */
#define false 0   /* Boolean false */
#define NULL  ((void *)0)   /* Null pointer constant */

/* ── Compiler built-ins ────────────────────────────────────────────────── */
/* Lean on Clang/GCC builtins so we avoid implementing them ourselves.
   These are available in freestanding mode.                               */
#define align_up(v, a)    __builtin_align_up(v, a)    /* round v up to next multiple of a   */
#define is_aligned(v, a)  __builtin_is_aligned(v, a)  /* true iff v is a multiple of a      */
#define offsetof(t, m)    __builtin_offsetof(t, m)    /* byte offset of member m in type t  */
#define va_list           __builtin_va_list            /* variable-argument list type        */
#define va_start          __builtin_va_start           /* initialise va_list to first vararg */
#define va_end            __builtin_va_end             /* clean up va_list                   */
#define va_arg            __builtin_va_arg             /* extract next argument from va_list */

/* ── Memory / paging ───────────────────────────────────────────────────── */
#define PAGE_SIZE 4096   /* RISC-V Sv32 smallest page = 4 KiB */

/* ── MMIO helpers ──────────────────────────────────────────────────────── */
/* volatile prevents the compiler from caching or reordering device reads.
   fence.i / fence ensure surrounding memory ops complete before/after.    */
#define MMIO_READ32(addr) \
    (*((volatile uint32_t *)(addr)))   /* read 32-bit MMIO register at addr */

#define MMIO_WRITE32(addr, val) \
    (*((volatile uint32_t *)(addr)) = (uint32_t)(val))  /* write 32-bit MMIO register */

/* Full memory fence — serialise all preceding stores before any load/store
   that follows (needed around VirtIO ring manipulation).                   */
#define MEM_FENCE() \
    __asm__ __volatile__("fence" ::: "memory")

/* Instruction fence — flush the instruction cache after writing code pages */
#define INST_FENCE() \
    __asm__ __volatile__("fence.i" ::: "memory")

/* ── Syscall numbers ───────────────────────────────────────────────────── */
/* Passed in register a3 on ecall entry; return value lands in a0.         */
#define SYS_PUTCHAR        1    /* putchar(char) → void                    */
#define SYS_GETCHAR        2    /* getchar()     → int (-1 = no data)      */
#define SYS_EXIT           3    /* exit()        → (no return)             */
#define SYS_READFILE       4    /* read file from TAR image                */
#define SYS_WRITEFILE      5    /* write file back to VirtIO disk          */
#define SYS_CRYPTO_HASH    6    /* SHA-256 via crypto_service IPC          */
#define SYS_CRYPTO_SIGN    7    /* Ed25519 sign via crypto_service IPC     */
#define SYS_KV_PUT         8    /* key-value put via kv_store IPC          */
#define SYS_KV_GET         9    /* key-value get via kv_store IPC          */
#define SYS_NET_BROADCAST  10   /* broadcast TX bytes via network_service  */
#define SYS_NET_FETCH      11   /* fetch next block from network_service   */
#define SYS_YIELD          12   /* cooperative yield to scheduler          */
#define SYS_IPC_WAIT       13   /* block until ipc_buf->type becomes != 0  */
#define SYS_IPC_NOTIFY     14   /* wake a blocked peer after writing reply  */
#define SYS_TRNG           15   /* fill buffer from RISC-V TRNG / CSR      */

/* ── C-runtime shims (common.c) ────────────────────────────────────────── */
/* Freestanding implementations — no host libc dependency. */
void  *memset (void *buf, char c, size_t n);              /* fill buf with c   */
void  *memcpy (void *dst, const void *src, size_t n);     /* copy n bytes      */
char  *strcpy (char *dst, const char *src);               /* copy NUL-term str */
char  *strncpy(char *dst, const char *src, size_t n);     /* bounded str copy  */
int    strcmp (const char *s1, const char *s2);           /* lexicographic cmp */
int    strncmp(const char *s1, const char *s2, size_t n); /* bounded str cmp   */
size_t strlen (const char *s);                            /* string length     */
void   printf (const char *fmt, ...);                     /* formatted console */

/* ── Panic ─────────────────────────────────────────────────────────────── */
/* Prints location + message then spins forever.  Used for unrecoverable
   kernel errors where returning would leave the system in an unknown state. */
#define PANIC(fmt, ...)                                                       \
    do {                                                                      \
        printf("PANIC %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        while (1) {}   /* halt — never return to caller */                    \
    } while (0)
