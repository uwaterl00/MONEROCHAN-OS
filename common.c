/*
 * common.c — Freestanding C-runtime support for Protheus OS.
 *
 * Implements the minimal libc subset declared in common.h.
 * All functions must be fully freestanding (no host headers, no CRT).
 * printf() calls putchar() which is provided by the kernel via SBI.
 *
 * Author:  m26steph@uwaterloo.ca
 */
#include "common.h"

/* ── Memory ──────────────────────────────────────────────────────────────
 * These are the only memory primitives needed by the kernel and services.
 * We do NOT use compiler-generated memset/memcpy because -nostdlib would
 * produce undefined references to __memset_chk etc. on some targets.
 */

/* memset — fill `n` bytes of `buf` with byte value `c`. */
void *memset(void *buf, char c, size_t n) {
    uint8_t *p = (uint8_t *)buf;       /* cast to byte pointer for byte-at-a-time write */
    while (n--)                         /* iterate over every byte */
        *p++ = (uint8_t)c;             /* write the fill byte and advance pointer */
    return buf;                         /* return original pointer (C standard) */
}

/* memcpy — copy `n` bytes from `src` to `dst` (regions must not overlap). */
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dst;         /* destination byte pointer */
    const uint8_t *s = (const uint8_t *)src;   /* source byte pointer      */
    while (n--)                                  /* copy one byte at a time  */
        *d++ = *s++;                             /* advance both pointers    */
    return dst;                                  /* return destination start */
}

/* ── Strings ─────────────────────────────────────────────────────────────
 * Simple byte-by-byte implementations.  Performance is irrelevant for a
 * research kernel that runs entirely cooperative on one hart.
 */

/* strcpy — copy NUL-terminated string from src to dst; returns dst. */
char *strcpy(char *dst, const char *src) {
    char *d = dst;                      /* save original dst for return value */
    while (*src)                        /* copy until NUL terminator */
        *d++ = *src++;                  /* advance both pointers */
    *d = '\0';                          /* write terminating NUL */
    return dst;                         /* return original destination */
}

/* strncpy — copy at most n bytes; zero-pads dst if src is shorter. */
char *strncpy(char *dst, const char *src, size_t n) {
    char *d = dst;                      /* save original dst */
    while (n && *src) {                 /* copy while bytes remain and src not NUL */
        *d++ = *src++;                  /* copy one byte */
        n--;                            /* decrement remaining count */
    }
    while (n--)                         /* zero-pad the rest of the field */
        *d++ = '\0';
    return dst;
}

/* strcmp — return <0, 0, >0 for s1 < s2, s1 == s2, s1 > s2. */
int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) { /* advance while chars match and non-NUL */
        s1++;
        s2++;
    }
    /* subtract as unsigned chars to match C standard semantics */
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/* strncmp — compare at most n characters. */
int strncmp(const char *s1, const char *s2, size_t n) {
    while (n--) {                       /* iterate for at most n chars */
        if (*s1 != *s2)                 /* mismatch found */
            return *(const unsigned char *)s1 - *(const unsigned char *)s2;
        if (!*s1)                       /* both strings ended simultaneously */
            return 0;
        s1++;                           /* advance first pointer */
        s2++;                           /* advance second pointer */
    }
    return 0;                           /* first n chars were equal */
}

/* strlen — count bytes before the NUL terminator. */
size_t strlen(const char *s) {
    size_t n = 0;                       /* byte counter */
    while (*s++)                        /* advance past each non-NUL byte */
        n++;
    return n;
}

/* ── printf ──────────────────────────────────────────────────────────────
 * Minimal formatted output.  Only the format specifiers actually used in
 * the kernel and services are implemented.  putchar() is provided by
 * kernel.c (SBI console call) and is declared below.
 *
 * Supported specifiers:
 *   %c  — single character
 *   %s  — NUL-terminated string
 *   %d  — signed decimal integer
 *   %u  — unsigned decimal integer
 *   %x  — unsigned 32-bit hex (always 8 digits, lower-case)
 *   %p  — pointer (0x prefix + 8 hex digits)
 *   %%  — literal percent sign
 */

/* putchar is defined in kernel.c; declared here for common.c's use. */
void putchar(char ch);

void printf(const char *fmt, ...) {
    va_list vargs;                      /* variadic argument list */
    va_start(vargs, fmt);               /* initialise list starting after fmt */

    while (*fmt) {                      /* walk every character of the format string */
        if (*fmt != '%') {              /* not a conversion specifier */
            putchar(*fmt++);            /* emit character as-is */
            continue;                   /* move to next character */
        }
        fmt++;                          /* consume the '%' */
        switch (*fmt) {
            case '\0':                  /* '%' at very end of format string */
                putchar('%');           /* emit the lonely percent */
                goto end;               /* jump out of loop */

            case '%':                   /* escaped percent '%%' */
                putchar('%');           /* emit a single literal '%' */
                break;

            case 'c':                   /* character: %c */
                /* char is promoted to int in variadic calls */
                putchar((char)va_arg(vargs, int));
                break;

            case 's': {                 /* NUL-terminated string: %s */
                const char *s = va_arg(vargs, const char *);
                if (!s) s = "(null)";   /* guard against NULL pointer */
                while (*s)              /* emit each character */
                    putchar(*s++);
                break;
            }

            case 'd': {                 /* signed decimal: %d */
                int v = va_arg(vargs, int);
                if (v < 0) {            /* negative: emit minus sign */
                    putchar('-');
                    v = -v;             /* make positive for digit extraction */
                }
                unsigned m = (unsigned)v; /* magnitude (handles INT_MIN correctly) */
                unsigned d = 1;           /* divisor starting at highest power of 10 */
                while (m / d > 9) d *= 10; /* find most significant digit's place */
                while (d) {               /* emit digits from most to least significant */
                    putchar('0' + m / d);  /* digit character */
                    m %= d;                /* remove emitted digit */
                    d /= 10;               /* move to next lower place */
                }
                break;
            }

            case 'u': {                 /* unsigned decimal: %u */
                unsigned v = va_arg(vargs, unsigned);
                unsigned d = 1;         /* divisor for most-significant digit */
                while (v / d > 9) d *= 10;
                while (d) {
                    putchar('0' + v / d);
                    v %= d;
                    d /= 10;
                }
                break;
            }

            case 'x': {                 /* 32-bit unsigned hex: %x (8 digits, no prefix) */
                unsigned v = va_arg(vargs, unsigned);
                /* iterate nibbles from most-significant (i=7) to least (i=0) */
                for (int i = 7; i >= 0; i--)
                    putchar("0123456789abcdef"[(v >> (i * 4)) & 0xf]);
                break;
            }

            case 'p': {                 /* pointer: %p  → 0xXXXXXXXX */
                putchar('0'); putchar('x');   /* emit '0x' prefix */
                unsigned v = (unsigned)(uintptr_t)va_arg(vargs, void *);
                for (int i = 7; i >= 0; i--)
                    putchar("0123456789abcdef"[(v >> (i * 4)) & 0xf]);
                break;
            }

            default:                    /* unknown specifier — emit verbatim */
                putchar('%');
                putchar(*fmt);
                break;
        }
        fmt++;                          /* advance past the specifier character */
    }
end:
    va_end(vargs);                      /* release variadic list resources */
}
