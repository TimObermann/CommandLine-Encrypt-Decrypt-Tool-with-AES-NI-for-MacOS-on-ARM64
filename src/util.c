#include "../include/util.h"

#include <stdio.h>
#include <stdlib.h>


size_t slen(const char* str) {
    int i = 0;
    while (*str != '\0') {
        i++;
        str++;
    }
    return i + 1;
}
void scopy(const char* src, char* dest) {
    while (*src != '\0') {
        *dest++ = *src++;
    }
    *dest = '\0';
}
int strcmp(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(const unsigned char*)str1 - *(const unsigned char*)str2;
}

int read_file(const char* filename, uint8_t** buff, size_t* file_size) {
    FILE* src = fopen(filename, "rb");
    if (src == NULL) {
        fprintf(stderr, "Could not open file %s for reading\n", filename);
        return 1;
    }

    fseek(src, 0, SEEK_END);
    *file_size = ftell(src);
    rewind(src);

    if (*file_size < 0) {
        fprintf(stderr, "Could not determine file size for file %s\n", filename);
        fclose(src);
        return 1;
    }

    *buff = (uint8_t*)malloc(*file_size);
    if (*buff == NULL) {
        fprintf(stderr, "Could not allocate space for file %s\n", filename);
        fclose(src);
        return 1;
    }

    size_t bytes_read = fread(*buff, 1, *file_size, src);
    if (bytes_read != *file_size) {
        fprintf(stderr, "Could not read all bytes from file %s\n", filename);
        fclose(src);
        free(*buff);
        *buff = NULL;
        return 1;
    }

    fclose(src);
    return 0;
}
int write_file(const char* filename, uint8_t* buff, size_t size) {
    FILE* f = fopen(filename, "wb");
    if (f == NULL) {
        fprintf(stderr, "Could not open file %s for writing\n", filename);
        return 1;
    }

    size_t bytes_written = fwrite(buff, 1, size, f);
    if (bytes_written != size) {
        fprintf(stderr, "Could not write to file %s\n", filename);
        fclose(f);
        return 1;
    }

    fclose(f);
    return 0;
}
