/*
 * common.h — Freestanding type definitions, string prototypes, and panic macro.
 *
 * This header replaces the C standard library entirely.  No host libc is
 * available when running freestanding on bare-metal RISC-V under OpenSBI.
 * Every primitive the kernel and services need is declared here and defined
 * in common.c (or, for printf, implemented inline via the SBI putchar).
 *
 * Author:  m26steph@uwaterloo.ca
 */
#pragma once                          /* include guard via pragma (supported by clang) */

/* ── Primitive integer types ───────────────────────────────────────────── */
/* RISC-V rv32 ABI: int=32-bit, long=32-bit, long long=64-bit             */
typedef int                bool;      /* boolean: 0=false, 1=true          */
typedef unsigned char      uint8_t;   /* 8-bit  unsigned byte              */
typedef unsigned short     uint16_t;  /* 16-bit unsigned halfword          */
typedef unsigned int       uint32_t;  /* 32-bit unsigned word              */
typedef unsigned long long uint64_t;  /* 64-bit unsigned doubleword        */
typedef uint32_t           size_t;    /* size type matches 32-bit pointers */
typedef uint32_t           uintptr_t; /* pointer-width unsigned integer    */
typedef uint32_t           paddr_t;   /* physical (machine) address        */
typedef uint32_t           vaddr_t;   /* virtual  (SV32 paged) address     */

/* ── Boolean constants ─────────────────────────────────────────────────── */
#define true  1                       /* boolean true  value               */
#define false 0                       /* boolean false value               */
#define NULL  ((void *)0)             /* null pointer constant             */

/* ── Compiler built-in helpers ─────────────────────────────────────────── */
/* These expand to __builtin_* which are always available in clang/gcc.    */
#define align_up(v, a)   __builtin_align_up((v), (a))   /* round v up to alignment a   */
#define is_aligned(v, a) __builtin_is_aligned((v), (a)) /* test alignment of v         */
#define offsetof(t, m)   __builtin_offsetof(t, m)       /* byte offset of member m     */
#define va_list          __builtin_va_list               /* variadic argument list type */
#define va_start         __builtin_va_start              /* initialise va_list          */
#define va_end           __builtin_va_end                /* finalise   va_list          */
#define va_arg           __builtin_va_arg                /* fetch next variadic arg     */

/* ── Memory / paging constants ─────────────────────────────────────────── */
#define PAGE_SIZE 4096                /* SV32 base page size in bytes      */

/* ── Syscall numbers (user → kernel ecall interface) ───────────────────── */
/* These constants are shared by the kernel (handle_syscall) and all       */
/* services (inline ecall wrappers).  The number is passed in register a3. */
#define SYS_PUTCHAR        1          /* write one character to console    */
#define SYS_GETCHAR        2          /* read  one character from console  */
#define SYS_EXIT           3          /* terminate the calling process     */
#define SYS_READFILE       4          /* read  a file from the TAR disk    */
#define SYS_WRITEFILE      5          /* write a file to   the TAR disk    */
#define SYS_CRYPTO_HASH    6          /* SHA-256 hash via crypto_service   */
#define SYS_CRYPTO_SIGN    7          /* Ed25519 sign via crypto_service   */
#define SYS_KV_PUT         8          /* store key→value via kv_store      */
#define SYS_KV_GET         9          /* fetch value by key via kv_store   */
#define SYS_NET_BROADCAST  10         /* broadcast TX via network_service  */
#define SYS_NET_FETCH      11         /* fetch block  via network_service  */
#define SYS_YIELD          12         /* voluntarily yield the CPU         */

/* ── C-runtime function prototypes (implemented in common.c) ───────────── */
void  *memset (void *buf, char c, size_t n);                      /* fill memory with byte c        */
void  *memcpy (void *dst, const void *src, size_t n);             /* copy n bytes src→dst           */
char  *strcpy (char *dst, const char *src);                       /* copy NUL-terminated string     */
char  *strncpy(char *dst, const char *src, size_t n);             /* copy at most n bytes of string */
int    strcmp (const char *s1, const char *s2);                   /* compare two strings            */
int    strncmp(const char *s1, const char *s2, size_t n);         /* compare at most n chars        */
size_t strlen (const char *s);                                    /* count chars before NUL         */
void   printf (const char *fmt, ...);                             /* formatted console output       */

/* ── Panic macro — prints location then halts forever ──────────────────── */
/* Uses a do-while(0) so it behaves as a single statement in all contexts.  */
#define PANIC(fmt, ...)                                                        \
    do {                                                                       \
        /* print file, line number, and the user-supplied message */          \
        printf("PANIC %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);  \
        /* spin forever — no recovery from a kernel panic */                  \
        while (1) {}                                                           \
    } while (0)

/* ── READ/WRITE_CSR helpers ────────────────────────────────────────────── */
/* Inline assembly to read/write RISC-V control and status registers.       */
#define READ_CSR(reg) ({                                  \
    uint32_t __v;                                         \
    __asm__ __volatile__("csrr %0, " #reg : "=r"(__v));  /* csrr rd, csr */ \
    __v;                                                  \
})
#define WRITE_CSR(reg, val)                                          \
    __asm__ __volatile__("csrw " #reg ", %0" :: "r"((uint32_t)(val))) /* csrw csr, rs1 */
