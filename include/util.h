#ifndef ENCRYPTCLITOOL_UTIL_H
#define ENCRYPTCLITOOL_UTIL_H

#include <stddef.h>
#include <stdint.h>

size_t slen(const char* str);
void scopy(const char* src, char* dest);
int strcmp(const char* str1, const char* str2);

int read_file(const char* filename, uint8_t** buff, size_t* file_size);
int write_file(const char* filename, uint8_t* buff, size_t size);

#endif //ENCRYPTCLITOOL_UTIL_H