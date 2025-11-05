#include <arm_neon.h>
#include <stdint.h>
#include <sys/random.h>

#include "../include/AES_with_NI.h"

#include <stdio.h>
#include <stdlib.h>

static const uint32_t RCON[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

/*
 *Bitsliced AES Sbox as per Boyar and Peralta,
 *"A depth-16 circuit for the AES S-box".
 *https://eprint.iacr.org/2011/332.pdf
 */

#define XOR(c,a,b) (c = (a)^(b))
#define AND(c,a,b) (c = (a)&(b))
#define XNOR(c,a,b) (c = ~((a) ^ (b)))

void sbox_bitsliced(uint16_t out[8],const uint16_t in[8]) {
  uint16_t U0,U1,U2,U3,U4,U5,U6,U7;
  uint16_t T1,T2,T3,T4,T5,T6,T7,T8,T9,T10,T11,T12,T13,T14,T15,T16,T17,T18,T19,T20,T21,T22,T23,T24,T25,T26,T27;
  uint16_t M1,M2,M3,M4,M5,M6,M7,M8,M9,M10,M11,M12,M13,M14,M15,M16,M17,M18,M19,M20,M21,M22,M23,M24,M25,M26,M27,M28,M29,M30,M31,M32,M33,M34,M35,M36,M37,M38,M39,M40,M41,M42,M43,M44,M45,M46,M47,M48,M49,M50,M51,M52,M53,M54,M55,M56,M57,M58,M59,M60,M61,M62,M63;
  uint16_t L0,L1,L2,L3,L4,L5,L6,L7,L8,L9,L10,L11,L12,L13,L14,L15,L16,L17,L18,L19,L20,L21,L22,L23,L24,L25,L26,L27,L28,L29;
  uint16_t S0,S1,S2,S3,S4,S5,S6,S7;

  U0=in[0];
  U1=in[1];
  U2=in[2];
  U3=in[3];
  U4=in[4];
  U5=in[5];
  U6=in[6];
  U7=in[7];

  XOR(T1,U0,U3);
  XOR(T2,U0,U5);
  XOR(T3,U0,U6);
  XOR(T4,U3,U5);
  XOR(T5,U4,U6);
  XOR(T6,T1,T5);
  XOR(T7,U1,U2);
  XOR(T8,U7,T6);
  XOR(T9,U7,T7);
  XOR(T10,T6,T7);
  XOR(T11,U1,U5);
  XOR(T12,U2,U5);
  XOR(T13,T3,T4);
  XOR(T14,T6,T11);
  XOR(T15,T5,T11);
  XOR(T16,T5,T12);
  XOR(T17,T9,T16);
  XOR(T18,U3,U7);
  XOR(T19,T7,T18);
  XOR(T20,T1,T19);
  XOR(T21,U6,U7);
  XOR(T22,T7,T21);
  XOR(T23,T2,T22);
  XOR(T24,T2,T10);
  XOR(T25,T20,T17);
  XOR(T26,T3,T16);
  XOR(T27,T1,T12);

  AND(M1,T13,T6);
  AND(M2,T23,T8);
  XOR(M3,T14,M1);
  AND(M4,T19,U7);
  XOR(M5,M4,M1);
  AND(M6,T3,T16);
  AND(M7,T22,T9);
  XOR(M8,T26,M6);
  AND(M9,T20,T17);
  XOR(M10,M9,M6);
  AND(M11,T1,T15);
  AND(M12,T4,T27);
  XOR(M13,M12,M11);
  AND(M14,T2,T10);
  XOR(M15,M14,M11);
  XOR(M16,M3,M2);
  XOR(M17,M5,T24);
  XOR(M18,M8,M7);
  XOR(M19,M10,M15);
  XOR(M20,M16,M13);
  XOR(M21,M17,M15);
  XOR(M22,M18,M13);
  XOR(M23,M19,T25);
  XOR(M24,M22,M23);
  AND(M25,M22,M20);
  XOR(M26,M21,M25);
  XOR(M27,M20,M21);
  XOR(M28,M23,M25);
  AND(M29,M28,M27);
  AND(M30,M26,M24);
  AND(M31,M20,M23);
  AND(M32,M27,M31);
  XOR(M33,M27,M25);
  AND(M34,M21,M22);
  AND(M35,M24,M34);
  XOR(M36,M24,M25);
  XOR(M37,M21,M29);
  XOR(M38,M32,M33);
  XOR(M39,M23,M30);
  XOR(M40,M35,M36);
  XOR(M41,M38,M40);
  XOR(M42,M37,M39);
  XOR(M43,M37,M38);
  XOR(M44,M39,M40);
  XOR(M45,M42,M41);
  AND(M46,M44,T6);
  AND(M47,M40,T8);
  AND(M48,M39,U7);
  AND(M49,M43,T16);
  AND(M50,M38,T9);
  AND(M51,M37,T17);
  AND(M52,M42,T15);
  AND(M53,M45,T27);
  AND(M54,M41,T10);
  AND(M55,M44,T13);
  AND(M56,M40,T23);
  AND(M57,M39,T19);
  AND(M58,M43,T3);
  AND(M59,M38,T22);
  AND(M60,M37,T20);
  AND(M61,M42,T1);
  AND(M62,M45,T4);
  AND(M63,M41,T2);

  XOR(L0,M61,M62);
  XOR(L1,M50,M56);
  XOR(L2,M46,M48);
  XOR(L3,M47,M55);
  XOR(L4,M54,M58);
  XOR(L5,M49,M61);
  XOR(L6,M62,L5);
  XOR(L7,M46,L3);
  XOR(L8,M51,M59);
  XOR(L9,M52,M53);
  XOR(L10,M53,L4);
  XOR(L11,M60,L2);
  XOR(L12,M48,M51);
  XOR(L13,M50,L0);
  XOR(L14,M52,M61);
  XOR(L15,M55,L1);
  XOR(L16,M56,L0);
  XOR(L17,M57,L1);
  XOR(L18,M58,L8);
  XOR(L19,M63,L4);
  XOR(L20,L0,L1);
  XOR(L21,L1,L7);
  XOR(L22,L3,L12);
  XOR(L23,L18,L2);
  XOR(L24,L15,L9);
  XOR(L25,L6,L10);
  XOR(L26,L7,L9);
  XOR(L27,L8,L10);
  XOR(L28,L11,L14);
  XOR(L29,L11,L17);

  XOR(S0,L6,L24);
  XOR(S1,L16,L26);
  XOR(S2,L19,L28);
  XOR(S3,L6,L21);
  XOR(S4,L20,L22);
  XOR(S5,L25,L29);
  XOR(S6,L13,L27);
  XOR(S7,L6,L23);

  out[0]=S0;
  out[1]=~S1;
  out[2]=~S2;
  out[3]=S3;
  out[4]=S4;
  out[5]=S5;
  out[6]=~S6;
  out[7]=~S7;
}
// void inv_sbox_bitsliced(uint16_t out[8], const uint16_t in[8]) {
//     uint16_t U0,U1,U2,U3,U4,U5,U6,U7;
//     uint16_t R5, R13, R17, R18, R19;
//     uint16_t Y5;
//     uint16_t T1,T2,T3,T4,T5,T6,T7,T8,T9,T10,T11,T12,T13,T14,T15,T16,T17,T18,T19,T20,T21,T22,T23,T24,T25,T26,T27;
//     uint16_t M1,M2,M3,M4,M5,M6,M7,M8,M9,M10,M11,M12,M13,M14,M15,M16,M17,M18,M19,M20,M21,M22,M23,M24,M25,M26,M27,M28,M29,M30,M31,M32,M33,M34,M35,M36,M37,M38,M39,M40,M41,M42,M43,M44,M45,M46,M47,M48,M49,M50,M51,M52,M53,M54,M55,M56,M57,M58,M59,M60,M61,M62,M63;
//     uint16_t P0,P1,P2,P3,P4,P5,P6,P7,P8,P9,P10,P11,P12,P13,P14,P15,P16,P17,P18,P19,P20,P21,P22,P23,P24,P25,P26,P27,P28,P29;
//     uint16_t W0,W1,W2,W3,W4,W5,W6,W7;
//
//     U0=in[0];
//     U1=in[1];
//     U2=in[2];
//     U3=in[3];
//     U4=in[4];
//     U5=in[5];
//     U6=in[6];
//     U7=in[7];
//
//     XOR(T23, U0, U3);
//     XNOR(T22, U1, U3);
//     XNOR(T2, U0, U1);
//     XOR(T1, U3, U4);
//     XNOR(T24, U4, U7);
//     XOR(R5, U6, U7);
//     XNOR(T8, U1, T23);
//     XOR(T19, T22, R5);
//     XOR(T19, T22, R5);
//     XNOR(T9, U7, T1);
//     XOR(T10, T2, T24);
//     XOR(T13, T2, R5);
//     XOR(T3, T1, R5);
//     XNOR(T25, U2, T1);
//     XOR(R13, U1, U6);
//     XNOR(T17, U2, T19);
//     XOR(T20, T24, R13);
//     XOR(T4, U4, T8);
//     XNOR(R17, U2, U5);
//     XNOR(R18, U5, U6);
//     XNOR(R19, U2, U4);
//     XOR(Y5,  U0 , R17);
//     XOR(T6, T22, R17);
//     XOR(T16, R13, R19);
//     XOR(T27, T1, R18);
//     XOR(T15, T10, T27);
//     XOR(T14, T10, R18);
//     XOR(T26, T3, T16);
//
//
//     AND(M1,T13,T6);
//     AND(M2,T23,T8);
//     XOR(M3,T14,M1);
//     AND(M4,T19,Y5);
//     XOR(M5,M4,M1);
//     AND(M6,T3,T16);
//     AND(M7,T22,T9);
//     XOR(M8,T26,M6);
//     AND(M9,T20,T17);
//     XOR(M10,M9,M6);
//     AND(M11,T1,T15);
//     AND(M12,T4,T27);
//     XOR(M13,M12,M11);
//     AND(M14,T2,T10);
//     XOR(M15,M14,M11);
//     XOR(M16,M3,M2);
//     XOR(M17,M5,T24);
//     XOR(M18,M8,M7);
//     XOR(M19,M10,M15);
//     XOR(M20,M16,M13);
//     XOR(M21,M17,M15);
//     XOR(M22,M18,M13);
//     XOR(M23,M19,T25);
//     XOR(M24,M22,M23);
//     AND(M25,M22,M20);
//     XOR(M26,M21,M25);
//     XOR(M27,M20,M21);
//     XOR(M28,M23,M25);
//     AND(M29,M28,M27);
//     AND(M30,M26,M24);
//     AND(M31,M20,M23);
//     AND(M32,M27,M31);
//     XOR(M33,M27,M25);
//     AND(M34,M21,M22);
//     AND(M35,M24,M34);
//     XOR(M36,M24,M25);
//     XOR(M37,M21,M29);
//     XOR(M38,M32,M33);
//     XOR(M39,M23,M30);
//     XOR(M40,M35,M36);
//     XOR(M41,M38,M40);
//     XOR(M42,M37,M39);
//     XOR(M43,M37,M38);
//     XOR(M44,M39,M40);
//     XOR(M45,M42,M41);
//     AND(M46,M44,T6);
//     AND(M47,M40,T8);
//     AND(M48,M39,Y5);
//     AND(M49,M43,T16);
//     AND(M50,M38,T9);
//     AND(M51,M37,T17);
//     AND(M52,M42,T15);
//     AND(M53,M45,T27);
//     AND(M54,M41,T10);
//     AND(M55,M44,T13);
//     AND(M56,M40,T23);
//     AND(M57,M39,T19);
//     AND(M58,M43,T3);
//     AND(M59,M38,T22);
//     AND(M60,M37,T20);
//     AND(M61,M42,T1);
//     AND(M62,M45,T4);
//     AND(M63,M41,T2);
//
//     XOR(P0, M52, M61);
//     XOR(P1, M58, M59);
//     XOR(P2, M54, M62);
//     XOR(P3, M47, M50);
//     XOR(P4, M48, M56);
//     XOR(P5, M46, M51);
//     XOR(P6, M49, M60);
//     XOR(P7, P0, P1);
//     XOR(P8, M50, M53);
//     XOR(P9, M55, M63);
//     XOR(P10, M57, P4);
//     XOR(P11, P0 , P3);
//     XOR(P12, M46, M48);
//     XOR(P13, M49, M51);
//     XOR(P14, M49, M62);
//     XOR(P15, M54, M59);
//     XOR(P16, M57, M61);
//     XOR(P17, M58, P2);
//     XOR(P18, M63, P5);
//     XOR(P19, P2, P3);
//     XOR(P20, P4, P6);
//     XOR(P22, P2, P7);
//     XOR(P23, P7, P8);
//     XOR(P24, P5, P7);
//     XOR(P25, P6 ,P10);
//     XOR(P26, P9 ,P11);
//     XOR(P27, P10 ,P18);
//     XOR(P28, P11 ,P25);
//     XOR(P29, P15 ,P20);
//     XOR(W0, P13 ,P22);
//     XOR(W1, P26, P29);
//     XOR(W2, P17, P28);
//     XOR(W3, P12, P22);
//     XOR(W4, P23, P27);
//     XOR(W5, P19, P24);
//     XOR(W6, P14, P23);
//     XOR(W7, P9, P16);
//
//     out[0] = W0;
//     out[1] = W1;
//     out[2] = W2;
//     out[3] = W3;
//     out[4] = W4;
//     out[5] = W5;
//     out[6] = W6;
//     out[7] = W7;
// }

static void pack_bitslice(uint16_t out[8], const uint8_t input[16]) {
    for (int bit = 0; bit < 8; bit++) {
        uint16_t w = 0;
        for (int i = 0; i < 16; i++) {
            w |= ((input[i] >> bit) & 1U) << i;
        }
        out[bit] = w;
    }
}
static void unpack_bitslice(uint8_t output[16], const uint16_t in[8]) {
    for (int i = 0; i < 16; i++) {
        uint8_t byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            byte |= ((in[bit] >> i) & 1U) << bit;
        }
        output[i] = byte;
    }
}

void sub_word_16(uint8_t dest[16], const uint8_t src[16]) {
    uint16_t in[8], out[8];
    pack_bitslice(in, src);
    sbox_bitsliced(out, in);
    unpack_bitslice(dest, out);
}
uint32_t sub_word_1(uint32_t w) {
    uint8_t input[16]  = {0};
    uint8_t output[16] = {0};
    uint16_t in[8], out[8];

    for (int i = 0; i < 4; i++) {
        input[i] = (w >> (8 * (3 - i))) & 0xFF;
    }

    pack_bitslice(in, input);
    sbox_bitsliced(out, in);
    unpack_bitslice(output, out);

    uint32_t result = 0;
    for (int i = 0; i < 4; i++) {
        result = (result << 8) | output[i];
    }

    return result;
}

uint32_t rot_word(uint32_t source) {
     return (source << 8) | (source >> 24);
}

void key_expansion_256_1k(const uint32_t* key, uint8x16_t* expanded_key_schedule) {
    uint32_t w[BLOCK_SIZE * (ROUNDS + 1)];
    __builtin_memcpy(w, key, KEY_LENGTH * sizeof(uint32_t));

    for (int i = KEY_LENGTH; i < BLOCK_SIZE * (ROUNDS + 1); i++) {
        uint32_t tmp = w[i - 1];

        if (i % KEY_LENGTH == 0) {
            tmp = sub_word_1(rot_word(tmp));
            tmp ^= RCON[(i / KEY_LENGTH) - 1];
        }
        else if (i % KEY_LENGTH == 4) {
            tmp = sub_word_1(tmp);
        }

        w[i] = w[i - KEY_LENGTH] ^ tmp;
    }

    for (int i = 0; i < ROUNDS + 1; ++i) {
        const uint8_t* source = (const uint8_t*) &w[i * BLOCK_SIZE];
        expanded_key_schedule[i] = vld1q_u8(source);
    }
}

void c(uint8_t* ciphertext, uint8_t* plaintext, const uint8x16_t* roundKey) {
    uint8x16_t state = vld1q_u8(plaintext);

    state = veorq_u8(state, roundKey[0]);

    for (int i = 1; i < ROUNDS; ++i) {
        state = vaeseq_u8(state, roundKey[i]);
        state = vaesmcq_u8(state);
    }

    state = vaeseq_u8(state, roundKey[ROUNDS]);
    vst1q_u8(ciphertext, state);
}

void ic(uint8_t* ciphertext, uint8_t* plaintext, const uint8x16_t* roundKey) {
    uint8x16_t state = vld1q_u8(ciphertext);

    state = veorq_u8(state, roundKey[0]);

    for (int i = 0; i < ROUNDS; ++i) {
        state = vaesdq_u8(state, roundKey[i]);
        state = vaesimcq_u8(state);
    }

    state = vaeseq_u8(state, roundKey[ROUNDS - 1]);
    vst1q_u8(plaintext, state);
}

void ctr_inc(uint8_t block[16]) {
    uint32_t* p = (uint32_t*) &block[12];
    (*p)++;
}

uint8_t* aes_256_encrypt(const uint8_t* bytes, size_t amount_of_bytes, const uint32_t* key) {

    uint8x16_t expanded_key_schedule[ROUNDS + 1];
    key_expansion_256_1k(key, expanded_key_schedule);

    _Alignas(16) uint8_t block[16];
    _Alignas(16) uint8_t key_stream_block[16];

    getentropy(block,12);
    block[12] = 0U;
    block[13] = 0U;
    block[14] = 0U;
    block[15] = 0U;

    uint8_t* ciphertext = (uint8_t*) malloc(12 + amount_of_bytes * sizeof(uint8_t));
    if (ciphertext == NULL) {
        fprintf(stderr, "Could not allocate memory\n");
        return NULL;
    }

    __builtin_memcpy(ciphertext, block, 12 * sizeof(uint8_t));

    for (int i = 0; i < amount_of_bytes; i += 16) {

        c(key_stream_block, block, expanded_key_schedule);

        for (int j = 0; j < (amount_of_bytes - i < 16 ? amount_of_bytes - i : 16); j++) {
            *(ciphertext + 12 + i + j) = *(bytes + i + j) ^ *(key_stream_block + j);
        }

        ctr_inc(block);
    }

    return ciphertext;
}

uint8_t* aes_256_decrypt(const uint8_t* bytes, size_t amount_of_bytes, const uint32_t* key) {
    uint8x16_t expanded_key_schedule[ROUNDS + 1];
    key_expansion_256_1k(key, expanded_key_schedule);


    _Alignas(16) uint8_t block[16];
    _Alignas(16) uint8_t key_stream_block[16];

    __builtin_memcpy(block, bytes, 12 * sizeof(uint8_t));
    block[12] = 0U;
    block[13] = 0U;
    block[14] = 0U;
    block[15] = 0U;
    bytes += 12;

    uint8_t* cleartext = (uint8_t*) malloc(amount_of_bytes * sizeof(uint8_t) - 12);
    size_t cleartext_len = amount_of_bytes - 12;

    if (cleartext == NULL) {
        fprintf(stderr, "Could not allocate memory\n");
        return NULL;
    }

    for (int i = 0; i < cleartext_len; i += 16) {

        c(key_stream_block, block, expanded_key_schedule);

        for (int j = 0; j < (cleartext_len - i < 16 ? cleartext_len - i : 16); j++) {
            *(cleartext + i + j) = *(bytes + i + j) ^ *(key_stream_block + j);
        }

        ctr_inc(block);
    }

    return cleartext;
}