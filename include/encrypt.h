#ifndef ENCRYPTCLITOOL_ENCRYPT_H
#define ENCRYPTCLITOOL_ENCRYPT_H

int encrypt_literal(const char* literal, const uint32_t* key);
int encrypt_folder_unified(const char* source_filename, const char* dest_filename, const uint32_t* key);
int encrypt_folder(const char* source_filename, const char* dest_filename, const uint32_t* key);
int encrypt_file(const char* source_filename, const char* dest_filename, const uint32_t* key);

#endif //ENCRYPTCLITOOL_ENCRYPT_H