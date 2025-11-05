#ifndef decryptCLITOOL_DECRYPT_H
#define decryptCLITOOL_DECRYPT_H

int decrypt_literal(const char* literal, const uint32_t* key);
int decrypt_folder_unified(const char* source_filename, const char* dest_filename, const uint32_t* key);
int decrypt_folder(const char* source_filename, const char* dest_filename, const uint32_t* key);
int decrypt_file(const char* source_filename, const char* dest_filename, const uint32_t* key);

#endif //decryptCLITOOL_DECRYPT_H