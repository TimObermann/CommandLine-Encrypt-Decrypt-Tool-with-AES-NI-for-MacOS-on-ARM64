#include "../include/sha256.h"

#include <stdlib.h>

#define min(a, b) (a < b ? a : b)

static uint32_t h_init[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

static uint32_t h0;
static uint32_t h1;
static uint32_t h2;
static uint32_t h3;
static uint32_t h4;
static uint32_t h5;
static uint32_t h6;
static uint32_t h7;



static uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t message_schedule[64];
uint8_t message[64];
uint32_t message_len = 0;
uint32_t message_offset = 0;

void sha256_init() {
    h0 = h_init[0];
    h1 = h_init[1];
    h2 = h_init[2];
    h3 = h_init[3];
    h4 = h_init[4];
    h5 = h_init[5];
    h6 = h_init[6];
    h7 = h_init[7];
}

void sha256_reset() {
    h0 = h_init[0];
    h1 = h_init[1];
    h2 = h_init[2];
    h3 = h_init[3];
    h4 = h_init[4];
    h5 = h_init[5];
    h6 = h_init[6];
    h7 = h_init[7];
    message_len = 0;
    message_offset = 0;
}

uint32_t rightrotate(const uint32_t num, uint8_t amount) {
    return  num >> amount | num << (32 - amount);
}

void process_block(const uint8_t block[HASH_BLOCK_SIZE]) {

    __builtin_memcpy(message_schedule, block, 16 * sizeof(uint8_t));

    for (int i = 16; i < 64; i++) {
        const uint32_t s0 = rightrotate(message_schedule[i - 15], 7) ^ rightrotate(message_schedule[i - 15], 18) ^ (message_schedule[i - 15] >> 3);
        const uint32_t s1 = rightrotate(message_schedule[i - 2], 17) ^ rightrotate(message_schedule[i - 2], 19) ^ (message_schedule[i - 2] >> 10);
        message_schedule[i] = message_schedule[i - 16] + s0 + message_schedule[i - 7] + s1;
    }
}

void compress(){

    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    uint32_t f = h5;
    uint32_t g = h6;
    uint32_t h = h7;

    uint32_t S0;
    uint32_t S1;
    uint32_t ch;
    uint32_t maj;
    uint32_t tmp1;
    uint32_t tmp2;

    for (int i = 0; i < 64; i++) {
        S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
        ch = (e & f) ^ ((~e) & g);
        tmp1 = h + S1 + ch + k[i] + message_schedule[i];

        S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        tmp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
}

void sha256_insert(uint8_t* bytes, uint32_t length) {
    message_len += length;
    uint32_t b_offset = 0;

    while (b_offset < length) {

        int copy_bytes = min(64 - message_offset, length - b_offset);
        __builtin_memcpy(message + message_offset, bytes + b_offset, copy_bytes);

        b_offset += copy_bytes;
        message_offset += copy_bytes;

        if(message_offset == 64) {
            process_block(message);
            compress();
            message_offset = 0;
        }
    }
}

uint32_t* sha256_finish() {

    unsigned long L = message_len << 3;
    message[message_offset++] = (uint8_t) 0x80;

    if(message_offset > 56) {
        while (message_offset < 64) {
            message[message_offset++] = 0;
        }

        process_block(message);
        compress();
        message_offset = 0;
    }


    while (message_offset < 56) {
        message[message_offset++] = 0;
    }
    for (int i = 0; i < 8; i++) {
        message[56 + i] = (uint8_t) (L >> (56 - (i << 3)));
    }

    process_block(message);
    compress();

    uint32_t* hash = (uint32_t*) malloc(8 * sizeof(uint32_t));

    hash[0] = h0;
    hash[1] = h1;
    hash[2] = h2;
    hash[3] = h3;
    hash[4] = h4;
    hash[5] = h5;
    hash[6] = h6;
    hash[7] = h7;

    return hash;
}