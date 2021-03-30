#pragma once
#include <stdint.h>

#define SHA1_DIGEST_SIZE 20

#define bswap_32(x) ((((x) & 0x000000FF) << 24) | \
                     (((x) & 0x0000FF00) << 8) | \
                     (((x) & 0x00FF0000) >> 8) | \
                     (((x) & 0xFF000000) >> 24))

#define SWAP(n) bswap_32(n)

#define BLOCKSIZE 32768

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

#define F1(B, C, D) (D ^ (B & (C ^ D)))
#define F2(B, C, D) (B ^ C ^ D)
#define F3(B, C, D) ((B & C) | (D & (B | C)))
#define F4(B, C, D) (B ^ C ^ D)

struct sha1_ctx {
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;

    uint32_t total[2];
    uint32_t buflen;
    uint32_t buffer[32];
};

static void sha1_process_block(const uint32_t* buffer, size_t len,
    struct sha1_ctx* ctx) {
    const uint32_t* words = buffer;
    size_t nwords = len / sizeof(uint32_t);
    const uint32_t* endp = words + nwords;
    uint32_t x[16];
    uint32_t a = ctx->A;
    uint32_t b = ctx->B;
    uint32_t c = ctx->C;
    uint32_t d = ctx->D;
    uint32_t e = ctx->E;
    uint32_t lolen = len;

    ctx->total[0] += lolen;
    ctx->total[1] += (len >> 31 >> 1) + (ctx->total[0] < lolen);

#define rol(x, n) (((x) << (n)) | ((uint32_t)(x) >> (32 - (n))))

#define M(I)                                                                   \
  (tm = x[I & 0x0f] ^ x[(I - 14) & 0x0f] ^ x[(I - 8) & 0x0f] ^                 \
        x[(I - 3) & 0x0f],                                                     \
   (x[I & 0x0f] = rol(tm, 1)))

#define R(A, B, C, D, E, F, K, M)                                              \
  do {                                                                         \
    E += rol(A, 5) + F(B, C, D) + K + M;                                       \
    B = rol(B, 30);                                                            \
  } while (0)

    while (words < endp) {
        uint32_t tm;
        int t;
        for (t = 0; t < 16; t++) {
            x[t] = SWAP(*words);
            words++;
        }

        R(a, b, c, d, e, F1, K1, x[0]);
        R(e, a, b, c, d, F1, K1, x[1]);
        R(d, e, a, b, c, F1, K1, x[2]);
        R(c, d, e, a, b, F1, K1, x[3]);
        R(b, c, d, e, a, F1, K1, x[4]);
        R(a, b, c, d, e, F1, K1, x[5]);
        R(e, a, b, c, d, F1, K1, x[6]);
        R(d, e, a, b, c, F1, K1, x[7]);
        R(c, d, e, a, b, F1, K1, x[8]);
        R(b, c, d, e, a, F1, K1, x[9]);
        R(a, b, c, d, e, F1, K1, x[10]);
        R(e, a, b, c, d, F1, K1, x[11]);
        R(d, e, a, b, c, F1, K1, x[12]);
        R(c, d, e, a, b, F1, K1, x[13]);
        R(b, c, d, e, a, F1, K1, x[14]);
        R(a, b, c, d, e, F1, K1, x[15]);
        R(e, a, b, c, d, F1, K1, M(16));
        R(d, e, a, b, c, F1, K1, M(17));
        R(c, d, e, a, b, F1, K1, M(18));
        R(b, c, d, e, a, F1, K1, M(19));
        R(a, b, c, d, e, F2, K2, M(20));
        R(e, a, b, c, d, F2, K2, M(21));
        R(d, e, a, b, c, F2, K2, M(22));
        R(c, d, e, a, b, F2, K2, M(23));
        R(b, c, d, e, a, F2, K2, M(24));
        R(a, b, c, d, e, F2, K2, M(25));
        R(e, a, b, c, d, F2, K2, M(26));
        R(d, e, a, b, c, F2, K2, M(27));
        R(c, d, e, a, b, F2, K2, M(28));
        R(b, c, d, e, a, F2, K2, M(29));
        R(a, b, c, d, e, F2, K2, M(30));
        R(e, a, b, c, d, F2, K2, M(31));
        R(d, e, a, b, c, F2, K2, M(32));
        R(c, d, e, a, b, F2, K2, M(33));
        R(b, c, d, e, a, F2, K2, M(34));
        R(a, b, c, d, e, F2, K2, M(35));
        R(e, a, b, c, d, F2, K2, M(36));
        R(d, e, a, b, c, F2, K2, M(37));
        R(c, d, e, a, b, F2, K2, M(38));
        R(b, c, d, e, a, F2, K2, M(39));
        R(a, b, c, d, e, F3, K3, M(40));
        R(e, a, b, c, d, F3, K3, M(41));
        R(d, e, a, b, c, F3, K3, M(42));
        R(c, d, e, a, b, F3, K3, M(43));
        R(b, c, d, e, a, F3, K3, M(44));
        R(a, b, c, d, e, F3, K3, M(45));
        R(e, a, b, c, d, F3, K3, M(46));
        R(d, e, a, b, c, F3, K3, M(47));
        R(c, d, e, a, b, F3, K3, M(48));
        R(b, c, d, e, a, F3, K3, M(49));
        R(a, b, c, d, e, F3, K3, M(50));
        R(e, a, b, c, d, F3, K3, M(51));
        R(d, e, a, b, c, F3, K3, M(52));
        R(c, d, e, a, b, F3, K3, M(53));
        R(b, c, d, e, a, F3, K3, M(54));
        R(a, b, c, d, e, F3, K3, M(55));
        R(e, a, b, c, d, F3, K3, M(56));
        R(d, e, a, b, c, F3, K3, M(57));
        R(c, d, e, a, b, F3, K3, M(58));
        R(b, c, d, e, a, F3, K3, M(59));
        R(a, b, c, d, e, F4, K4, M(60));
        R(e, a, b, c, d, F4, K4, M(61));
        R(d, e, a, b, c, F4, K4, M(62));
        R(c, d, e, a, b, F4, K4, M(63));
        R(b, c, d, e, a, F4, K4, M(64));
        R(a, b, c, d, e, F4, K4, M(65));
        R(e, a, b, c, d, F4, K4, M(66));
        R(d, e, a, b, c, F4, K4, M(67));
        R(c, d, e, a, b, F4, K4, M(68));
        R(b, c, d, e, a, F4, K4, M(69));
        R(a, b, c, d, e, F4, K4, M(70));
        R(e, a, b, c, d, F4, K4, M(71));
        R(d, e, a, b, c, F4, K4, M(72));
        R(c, d, e, a, b, F4, K4, M(73));
        R(b, c, d, e, a, F4, K4, M(74));
        R(a, b, c, d, e, F4, K4, M(75));
        R(e, a, b, c, d, F4, K4, M(76));
        R(d, e, a, b, c, F4, K4, M(77));
        R(c, d, e, a, b, F4, K4, M(78));
        R(b, c, d, e, a, F4, K4, M(79));

        a = ctx->A += a;
        b = ctx->B += b;
        c = ctx->C += c;
        d = ctx->D += d;
        e = ctx->E += e;
    }
}

static const unsigned char fillbuf[64] = { 0x80, 0 };

static void sha1_init_ctx(struct sha1_ctx* ctx) {
    ctx->A = 0x67452301;
    ctx->B = 0xefcdab89;
    ctx->C = 0x98badcfe;
    ctx->D = 0x10325476;
    ctx->E = 0xc3d2e1f0;

    ctx->total[0] = ctx->total[1] = 0;
    ctx->buflen = 0;
}

static void set_uint32(char* cp, uint32_t v) { memcpy(cp, &v, sizeof v); }

static void* sha1_read_ctx(const struct sha1_ctx* ctx, char* resbuf) {
    char* r = resbuf;
    set_uint32(r + 0 * sizeof ctx->A, SWAP(ctx->A));
    set_uint32(r + 1 * sizeof ctx->B, SWAP(ctx->B));
    set_uint32(r + 2 * sizeof ctx->C, SWAP(ctx->C));
    set_uint32(r + 3 * sizeof ctx->D, SWAP(ctx->D));
    set_uint32(r + 4 * sizeof ctx->E, SWAP(ctx->E));

    return resbuf;
}

static void* sha1_finish_ctx(struct sha1_ctx* ctx, char* resbuf) {
    uint32_t bytes = ctx->buflen;
    size_t size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;

    ctx->total[0] += bytes;
    if (ctx->total[0] < bytes)
        ++ctx->total[1];

    ctx->buffer[size - 2] = SWAP((ctx->total[1] << 3) | (ctx->total[0] >> 29));
    ctx->buffer[size - 1] = SWAP(ctx->total[0] << 3);

    memcpy(&((char*)ctx->buffer)[bytes], fillbuf, (size - 2) * 4 - bytes);

    sha1_process_block(ctx->buffer, size * 4, ctx);

    return sha1_read_ctx(ctx, resbuf);
}

static void sha1_process_bytes(const char* buffer, size_t len,
    struct sha1_ctx* ctx) {
    if (ctx->buflen != 0) {
        size_t left_over = ctx->buflen;
        size_t add = 128 - left_over > len ? len : 128 - left_over;

        memcpy(&((char*)ctx->buffer)[left_over], buffer, add);
        ctx->buflen += add;

        if (ctx->buflen > 64) {
            sha1_process_block(ctx->buffer, ctx->buflen & ~63, ctx);

            ctx->buflen &= 63;
            memcpy(ctx->buffer, &((char*)ctx->buffer)[(left_over + add) & ~63],
                ctx->buflen);
        }

        buffer = (const char*)buffer + add;
        len -= add;
    }

    if (len >= 64) {
        {
            sha1_process_block((uint32_t*)buffer, len & ~63, ctx);
            buffer = (const char*)buffer + (len & ~63);
            len &= 63;
        }
    }

    if (len > 0) {
        size_t left_over = ctx->buflen;

        memcpy(&((char*)ctx->buffer)[left_over], buffer, len);
        left_over += len;
        if (left_over >= 64) {
            sha1_process_block(ctx->buffer, 64, ctx);
            left_over -= 64;
            memcpy(ctx->buffer, &ctx->buffer[16], left_over);
        }
        ctx->buflen = left_over;
    }
}

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
static void* sha1_buffer(const char* buffer, size_t len, char* resblock) {
    struct sha1_ctx ctx;

    /* Initialize the computation context.  */
    sha1_init_ctx(&ctx);

    /* Process whole buffer but last len % 64 bytes.  */
    sha1_process_bytes(buffer, len, &ctx);

    /* Put result in desired memory area.  */
    return sha1_finish_ctx(&ctx, resblock);
}

/*
https://raw.githubusercontent.com/coreutils/gnulib/master/lib/sha1.c
*/
