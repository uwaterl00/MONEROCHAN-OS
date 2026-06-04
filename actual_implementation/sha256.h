/*
 * Protheus OS - SHA-256 (FIPS 180-4)
 *
 * Freestanding C implementation — no libc required.
 * Used exclusively inside crypto_service (isolated, no network access).
 *
 * Author:  m26steph@uwaterloo.ca
 * Credits: Nicolae Carabut (Dispatch Labs) - architectural inspiration
 * License: The Free License (https://github.com/codemodify/TheFreeLicense)
 */
#pragma once

#include "../kernel/common.h"

/* ── SHA-256 context ─────────────────────────────────────────────────────── */
#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint32_t count[2];         /* bit count lo/hi */
    uint8_t  buf[SHA256_BLOCK_SIZE];
} sha256_ctx;

/* ── Helpers ─────────────────────────────────────────────────────────────── */
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)       (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)      (ROTR32(x,  7) ^ ROTR32(x, 18) ^ ((x) >>  3))
#define SIG1(x)      (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

    for (int i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((uint32_t) data[j]     << 24)
             | ((uint32_t) data[j + 1] << 16)
             | ((uint32_t) data[j + 2] <<  8)
             | ((uint32_t) data[j + 3]);
    for (int i = 16; i < 64; i++)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g)  + K[i] + m[i];
        t2 = EP0(a)     + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    uint32_t i, j;
    j = ctx->count[0];
    ctx->count[0] += (uint32_t) len << 3;
    if (ctx->count[0] < j)
        ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    j = (j >> 3) & 63;

    if ((j + len) > 63) {
        i = 64 - j;
        memcpy(&ctx->buf[j], data, i);
        sha256_transform(ctx, ctx->buf);
        for (; i + 63 < len; i += 64)
            sha256_transform(ctx, &data[i]);
        j = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buf[j], &data[i], len - i);
}

static void sha256_final(sha256_ctx *ctx, uint8_t *digest) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++)
        finalcount[i] = (uint8_t)
            (ctx->count[(i >= 4) ? 0 : 1] >> ((3 - (i & 3)) * 8));

    sha256_update(ctx, (const uint8_t *) "\x80", 1);
    while ((ctx->count[0] & 504) != 448)
        sha256_update(ctx, (const uint8_t *) "\0", 1);
    sha256_update(ctx, finalcount, 8);

    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
        digest[i] = (uint8_t)
            (ctx->state[i >> 2] >> ((3 - (i & 3)) * 8));
}

/* Public one-shot API */
static inline void sha256(const uint8_t *data, size_t len, uint8_t *digest) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}
