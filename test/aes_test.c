
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/AES_with_NI.h"

int main(void) {

    uint32_t key[8] = {
        0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
        0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4
    };

    char s[4] = "123";

    uint8_t* c = aes_256_encrypt((uint8_t*)s, 4, key);
    uint8_t* r = aes_256_decrypt(c, 12 + 4, key);

    char rr[5];
    rr[0] = (char)r[0];
    rr[1] = (char)r[1];
    rr[2] = (char)r[2];
    rr[3] = (char)r[3];
    rr[4] = (char)'\0';

    printf("<%s>:<%s>\n", s, rr);

    free(r);
}
