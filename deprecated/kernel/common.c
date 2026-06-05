/*
 * Protheus OS — Common C-runtime Support
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */
#include "common.h"

/* ── Memory ────────────────────────────────────────────────────────────── */

void *memset(void *buf, char c, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n--) *p++ = (uint8_t)c;
    return buf;
}

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

/* ── Strings ───────────────────────────────────────────────────────────── */

char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while (*src) *d++ = *src++;
    *d = '\0';
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
    char *d = dst;
    while (n && *src) { *d++ = *src++; n--; }
    while (n--)        *d++ = '\0';
    return dst;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) { s1++; s2++; }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n--) {
        if (*s1 != *s2) return *(const unsigned char *)s1
                               - *(const unsigned char *)s2;
        if (!*s1) return 0;
        s1++; s2++;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++) n++;
    return n;
}

/* ── printf (putchar provided by kernel) ───────────────────────────────── */
void putchar(char ch);

void printf(const char *fmt, ...) {
    va_list vargs;
    va_start(vargs, fmt);
    while (*fmt) {
        if (*fmt != '%') { putchar(*fmt++); continue; }
        fmt++;
        switch (*fmt) {
            case '\0': putchar('%'); goto end;
            case '%':  putchar('%'); break;
            case 'c':  putchar((char)va_arg(vargs, int)); break;
            case 's': {
                const char *s = va_arg(vargs, const char *);
                if (!s) s = "(null)";
                while (*s) putchar(*s++);
                break;
            }
            case 'd': {
                int v = va_arg(vargs, int);
                if (v < 0) { putchar('-'); v = -v; }
                unsigned m = (unsigned)v, d = 1;
                while (m / d > 9) d *= 10;
                while (d) { putchar('0' + m / d); m %= d; d /= 10; }
                break;
            }
            case 'u': {
                unsigned v = va_arg(vargs, unsigned), d = 1;
                while (v / d > 9) d *= 10;
                while (d) { putchar('0' + v / d); v %= d; d /= 10; }
                break;
            }
            case 'x': {
                unsigned v = va_arg(vargs, unsigned);
                for (int i = 7; i >= 0; i--)
                    putchar("0123456789abcdef"[(v >> (i * 4)) & 0xf]);
                break;
            }
            case 'p': {
                putchar('0'); putchar('x');
                unsigned v = (unsigned)(uintptr_t)va_arg(vargs, void *);
                for (int i = 7; i >= 0; i--)
                    putchar("0123456789abcdef"[(v >> (i * 4)) & 0xf]);
                break;
            }
            default: putchar('%'); putchar(*fmt); break;
        }
        fmt++;
    }
end:
    va_end(vargs);
}
