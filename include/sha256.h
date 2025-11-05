#ifndef ENCRYPTCLITOOL_SHA256_H
#define ENCRYPTCLITOOL_SHA256_H

#include <stdint.h>


#define DIGEST_SIZE 32
#define HASH_BLOCK_SIZE 64

void sha256_init();
void sha256_insert(uint8_t* bytes, uint32_t length);
uint32_t* sha256_finish();
void sha256_reset();

#endif //ENCRYPTCLITOOL_SHA256_H