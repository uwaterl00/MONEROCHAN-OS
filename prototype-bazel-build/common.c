/*
 * Protheus OS — Common C-runtime Support
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) — architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 *
 * Freestanding replacement for the subset of libc used across all kernel
 * and service translation units.  No host headers are included.
 */
#include "common.h"

/* ── Memory ────────────────────────────────────────────────────────────── */

/*
 * memset — fill `n` bytes of `buf` with byte value `c`.
 * Returns `buf` so callers can chain: memset(alloc(), 0, sz).
 */
void *memset(void *buf, char c, size_t n) {
    uint8_t *p = (uint8_t *)buf;   /* work through buffer byte-by-byte     */
    while (n--)                    /* decrement n; stop when it hits 0     */
        *p++ = (uint8_t)c;         /* write byte, advance pointer          */
    return buf;                    /* return original pointer to caller    */
}

/*
 * memcpy — copy `n` bytes from `src` to `dst` (no overlap assumed).
 * Returns `dst`.
 */
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dst;         /* mutable write pointer    */
    const uint8_t *s = (const uint8_t *)src;   /* read-only source pointer */
    while (n--)          /* copy byte-by-byte; compiler will auto-vectorise */
        *d++ = *s++;
    return dst;
}

/* ── Strings ───────────────────────────────────────────────────────────── */

/*
 * strcpy — copy NUL-terminated string from `src` to `dst`.
 * Caller must ensure dst is large enough for strlen(src)+1 bytes.
 */
char *strcpy(char *dst, const char *src) {
    char *d = dst;              /* remember the start of dst for return     */
    while (*src)                /* copy until NUL terminator in source      */
        *d++ = *src++;
    *d = '\0';                  /* write terminating NUL to destination     */
    return dst;
}

/*
 * strncpy — copy at most `n` bytes from `src` to `dst`.
 * If `src` is shorter than n, the remainder of dst is zero-padded.
 * NOTE: does NOT guarantee NUL-termination when src is exactly n bytes.
 */
char *strncpy(char *dst, const char *src, size_t n) {
    char *d = dst;
    while (n && *src) {    /* copy as long as we have room AND src has data */
        *d++ = *src++;
        n--;
    }
    while (n--)            /* pad remaining bytes with NUL                  */
        *d++ = '\0';
    return dst;
}

/*
 * strcmp — lexicographic comparison of two NUL-terminated strings.
 * Returns 0 if equal, <0 if s1 < s2, >0 if s1 > s2.
 */
int strcmp(const char *s1, const char *s2) {
    /* advance while characters match and neither string has ended */
    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }
    /* difference of first differing characters (or 0 if both NUL) */
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/*
 * strncmp — compare up to `n` characters of two strings.
 * Returns 0 if equal within n chars, otherwise sign of first difference.
 */
int strncmp(const char *s1, const char *s2, size_t n) {
    while (n--) {                                    /* count down limit       */
        if (*s1 != *s2)                              /* mismatch found         */
            return *(const unsigned char *)s1
                 - *(const unsigned char *)s2;       /* return signed diff     */
        if (!*s1)                                    /* both NUL simultaneously */
            return 0;
        s1++;
        s2++;
    }
    return 0;   /* all n characters matched */
}

/*
 * strlen — return number of bytes before the NUL terminator.
 */
size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++)   /* increment pointer; stop when it was pointing at NUL */
        n++;
    return n;
}

/* ── printf (putchar provided by kernel) ───────────────────────────────── */
/*
 * putchar is implemented in kernel.c (via SBI console) and declared here
 * so that common.c can call it without a circular include.
 */
void putchar(char ch);

/*
 * printf — minimal subset: %c %s %d %u %x %p.
 * No floating point, no width/precision — this is a kernel printf.
 * Uses SBI putchar for each character (no buffering).
 */
void printf(const char *fmt, ...) {
    va_list vargs;
    va_start(vargs, fmt);         /* initialise vararg iterator at `fmt`    */

    while (*fmt) {                /* iterate over every character in format */
        if (*fmt != '%') {
            putchar(*fmt++);      /* literal character — emit directly       */
            continue;
        }
        fmt++;                    /* consume the '%'                         */

        switch (*fmt) {
            case '\0':            /* '%' at end of string — emit '%' safely  */
                putchar('%');
                goto end;

            case '%':             /* '%%' → literal '%'                      */
                putchar('%');
                break;

            case 'c':             /* '%c' → single character argument        */
                putchar((char)va_arg(vargs, int));
                break;

            case 's': {           /* '%s' → NUL-terminated string argument   */
                const char *s = va_arg(vargs, const char *);
                if (!s) s = "(null)";       /* guard against NULL strings    */
                while (*s) putchar(*s++);
                break;
            }

            case 'd': {           /* '%d' → signed decimal integer           */
                int v = va_arg(vargs, int);
                if (v < 0) {
                    putchar('-');  /* emit minus sign for negatives           */
                    v = -v;        /* negate to work with positive value      */
                }
                unsigned m = (unsigned)v;  /* magnitude                      */
                unsigned d = 1;
                while (m / d > 9) d *= 10; /* find highest decimal digit     */
                while (d) {
                    putchar('0' + m / d);   /* emit each digit high-to-low   */
                    m %= d;                 /* strip the emitted digit        */
                    d /= 10;                /* move to next lower place       */
                }
                break;
            }

            case 'u': {           /* '%u' → unsigned decimal integer         */
                unsigned v = va_arg(vargs, unsigned);
                unsigned d = 1;
                while (v / d > 9) d *= 10; /* find highest decimal digit     */
                while (d) {
                    putchar('0' + v / d);
                    v %= d;
                    d /= 10;
                }
                break;
            }

            case 'x': {           /* '%x' → lowercase hex, always 8 digits   */
                unsigned v = va_arg(vargs, unsigned);
                for (int i = 7; i >= 0; i--)   /* emit nibble from MSB down  */
                    putchar("0123456789abcdef"[(v >> (i * 4)) & 0xf]);
                break;
            }

            case 'p': {           /* '%p' → pointer as 0x<8-hex-digits>      */
                putchar('0'); putchar('x');
                unsigned v = (unsigned)(uintptr_t)va_arg(vargs, void *);
                for (int i = 7; i >= 0; i--)
                    putchar("0123456789abcdef"[(v >> (i * 4)) & 0xf]);
                break;
            }

            default:              /* unknown specifier — emit literally       */
                putchar('%');
                putchar(*fmt);
                break;
        }
        fmt++;   /* advance past the format specifier character              */
    }
end:
    va_end(vargs);   /* release va_list resources                            */
}
