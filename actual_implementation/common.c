/*
 * Protheus OS - Common C-runtime Support
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */
#include "common.h"

/* ── Memory primitives ───────────────────────────────────────────────────── */

void *memset(void *buf, char c, size_t n) {
    uint8_t *p = (uint8_t *) buf;
    while (n--)
        *p++ = (uint8_t) c;
    return buf;
}

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *) dst;
    const uint8_t *s = (const uint8_t *) src;
    while (n--)
        *d++ = *s++;
    return dst;
}

/* ── String primitives ───────────────────────────────────────────────────── */

char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while (*src)
        *d++ = *src++;
    *d = '\0';
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
    char *d = dst;
    while (n && *src) {
        *d++ = *src++;
        n--;
    }
    while (n--)
        *d++ = '\0';
    return dst;
}

int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2)
            break;
        s1++;
        s2++;
    }
    return *(const unsigned char *) s1 - *(const unsigned char *) s2;
}

int strncmp(const char *s1, const char *s2, size_t n) {
    while (n-- && *s1 && *s2) {
        if (*s1 != *s2)
            return *(const unsigned char *) s1 - *(const unsigned char *) s2;
        s1++;
        s2++;
    }
    if (n == (size_t)-1)
        return 0;
    return *(const unsigned char *) s1 - *(const unsigned char *) s2;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++)
        n++;
    return n;
}

/* ── Formatted output ────────────────────────────────────────────────────── */

/* putchar() is provided by the kernel (SBI call). */
void putchar(char ch);

void printf(const char *fmt, ...) {
    va_list vargs;
    va_start(vargs, fmt);

    while (*fmt) {
        if (*fmt != '%') {
            putchar(*fmt++);
            continue;
        }
        fmt++;           /* skip '%' */
        switch (*fmt) {
            case '\0':
                putchar('%');
                goto end;
            case '%':
                putchar('%');
                break;
            case 'c':
                putchar((char) va_arg(vargs, int));
                break;
            case 's': {
                const char *s = va_arg(vargs, const char *);
                if (!s) s = "(null)";
                while (*s)
                    putchar(*s++);
                break;
            }
            case 'd': {
                int value = va_arg(vargs, int);
                if (value < 0) {
                    putchar('-');
                    value = -value;
                }
                unsigned mag = (unsigned) value;
                unsigned div = 1;
                while (mag / div > 9)
                    div *= 10;
                while (div) {
                    putchar('0' + mag / div);
                    mag %= div;
                    div /= 10;
                }
                break;
            }
            case 'u': {
                unsigned value = va_arg(vargs, unsigned);
                unsigned div = 1;
                while (value / div > 9)
                    div *= 10;
                while (div) {
                    putchar('0' + value / div);
                    value %= div;
                    div /= 10;
                }
                break;
            }
            case 'x': {
                unsigned value = va_arg(vargs, unsigned);
                for (int i = 7; i >= 0; i--) {
                    unsigned nibble = (value >> (i * 4)) & 0xf;
                    putchar("0123456789abcdef"[nibble]);
                }
                break;
            }
            case 'p': {
                /* pointer: prefix 0x then 8 hex digits */
                putchar('0');
                putchar('x');
                unsigned value = (unsigned)(uintptr_t) va_arg(vargs, void *);
                for (int i = 7; i >= 0; i--) {
                    unsigned nibble = (value >> (i * 4)) & 0xf;
                    putchar("0123456789abcdef"[nibble]);
                }
                break;
            }
            default:
                putchar('%');
                putchar(*fmt);
                break;
        }
        fmt++;
    }
end:
    va_end(vargs);
}
