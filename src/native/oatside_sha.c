#include <stdint.h>

#if defined(_WIN32)
#define OATSIDE_EXPORT __declspec(dllexport)
#else
#define OATSIDE_EXPORT
#endif

static inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

OATSIDE_EXPORT void oatside_compress(const uint8_t *block, const uint32_t *k, uint8_t *out) {
    uint32_t w[64];
    for (int t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[4 * t] << 24) | ((uint32_t)block[4 * t + 1] << 16) |
               ((uint32_t)block[4 * t + 2] << 8) | (uint32_t)block[4 * t + 3];
    }
    for (int t = 16; t < 64; t++) {
        uint32_t x = w[t - 15], y = w[t - 2];
        uint32_t s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
        uint32_t s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    uint32_t e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    for (int t = 0; t < 64; t++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + k[t] + w[t];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    uint32_t r[8] = {a, b, c, d, e, f, g, h};
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(r[i] >> 24);
        out[4 * i + 1] = (uint8_t)(r[i] >> 16);
        out[4 * i + 2] = (uint8_t)(r[i] >> 8);
        out[4 * i + 3] = (uint8_t)r[i];
    }
}
