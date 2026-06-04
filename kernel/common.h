/*
 * Protheus OS — Common Types & Utilities
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * Target: RISC-V rv32ima, OpenSBI, QEMU virt.
 * Fully freestanding — no host libc.
 */
#pragma once

/* ── Primitive types ───────────────────────────────────────────────────── */
typedef int                bool;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
typedef uint32_t           size_t;
typedef uint32_t           uintptr_t;
typedef uint32_t           paddr_t;   /* physical address */
typedef uint32_t           vaddr_t;   /* virtual  address */

#define true  1
#define false 0
#define NULL  ((void *)0)

/* ── Compiler built-ins ────────────────────────────────────────────────── */
#define align_up(v, a)    __builtin_align_up(v, a)
#define is_aligned(v, a)  __builtin_is_aligned(v, a)
#define offsetof(t, m)    __builtin_offsetof(t, m)
#define va_list           __builtin_va_list
#define va_start          __builtin_va_start
#define va_end            __builtin_va_end
#define va_arg            __builtin_va_arg

/* ── Memory / paging ───────────────────────────────────────────────────── */
#define PAGE_SIZE 4096

/* ── Syscall numbers ───────────────────────────────────────────────────── */
#define SYS_PUTCHAR        1
#define SYS_GETCHAR        2
#define SYS_EXIT           3
#define SYS_READFILE       4
#define SYS_WRITEFILE      5
#define SYS_CRYPTO_HASH    6
#define SYS_CRYPTO_SIGN    7
#define SYS_KV_PUT         8
#define SYS_KV_GET         9
#define SYS_NET_BROADCAST  10
#define SYS_NET_FETCH      11
#define SYS_YIELD          12

/* ── C-runtime shims (common.c) ────────────────────────────────────────── */
void  *memset (void *buf, char c, size_t n);
void  *memcpy (void *dst, const void *src, size_t n);
char  *strcpy (char *dst, const char *src);
char  *strncpy(char *dst, const char *src, size_t n);
int    strcmp (const char *s1, const char *s2);
int    strncmp(const char *s1, const char *s2, size_t n);
size_t strlen (const char *s);
void   printf (const char *fmt, ...);

/* ── Panic ─────────────────────────────────────────────────────────────── */
#define PANIC(fmt, ...)                                                       \
    do {                                                                      \
        printf("PANIC %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
        while (1) {}                                                          \
    } while (0)
