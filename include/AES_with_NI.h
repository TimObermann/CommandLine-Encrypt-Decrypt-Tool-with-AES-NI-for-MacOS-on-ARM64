#ifndef ENCRYPTCLITOOL_AES_WITH_NI_H
#define ENCRYPTCLITOOL_AES_WITH_NI_H

#define ROUNDS 14
#define KEY_LENGTH 8
#define BLOCK_SIZE 4

uint8_t* aes_256_encrypt(const uint8_t* bytes, size_t amount_of_bytes, const uint32_t* key);
uint8_t* aes_256_decrypt(const uint8_t* bytes, size_t amount_of_bytes, const uint32_t* key);

#endif //ENCRYPTCLITOOL_AES_WITH_NI_H