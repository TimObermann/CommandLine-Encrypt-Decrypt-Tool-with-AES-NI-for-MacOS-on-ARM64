#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/random.h>

#include "../include/encrypt.h"
#include "../include/AES_with_NI.h"
#include "../include/sha256.h"
#include "../include/util.h"


#define HELP_STRING "\nThe Encryption Tool allows you to encrypt literals, files, and directories:\n\nencrypt [-flags]\n\nPossible flags:\n-l <literal> -- provide a literal to encrypt\n-f <path_to_file> -- provide a file to encrypt\n-r <path_to_directory> -- provide a directory to recursively encrypt\n-d <path_to_directory/file> -- sets the target\n-k <literal> -- provide a key literal for encryption\n-g -- randomly generate a key for the encryption\n-p <path_to_file> -- provide a key.secret file, in the same directory, that contains the secret key to use in the encryption\n\n@Tim Obermann"

void freeAllNotNull(char* source_filename, char* destination_filename, char* literal, uint32_t* secret_key) {
    if (source_filename != NULL) free(source_filename);
    if (destination_filename != NULL) free(destination_filename);
    if (literal != NULL) free(literal);
    if (secret_key != NULL) free(secret_key);
}

int encrypt_file(const char* source_filename, const char* dest_filename, const uint32_t* key) {

    uint8_t* buff = NULL;
    size_t file_size = 0;;
    if (read_file(source_filename, &buff, &file_size)) {
        fprintf(stderr, "CRITICAL ERROR: Could not encrypt file %s\n", source_filename);
        return 1;
    }

    uint8_t* encrypted_bytes = aes_256_encrypt(buff, file_size, key);
    free(buff);

    if (write_file(dest_filename, encrypted_bytes, file_size + 12)) {
        fprintf(stderr, "CRITICAL ERROR: Could not encrypt file %s\n", dest_filename);
        free(encrypted_bytes);
        return 1;
    }

    free(encrypted_bytes);
    return 0;
}

int encrypt_folder(const char* source_filename, const char* dest_filename, const uint32_t* key) {
    DIR* dir;
    struct dirent* entry;
    struct stat st;
    int result = 0;

    if (mkdir(dest_filename, 0755) != 0) {
        if (errno != EEXIST) {
            fprintf(stderr, "Error: Could not create directory '%s'\n", dest_filename);
            return -1;
        }
    }

    if ((dir = opendir(source_filename)) == NULL) {
        fprintf(stderr, "Error: Could not open source directory '%s'\n", source_filename);
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char srcPath[1024];
        char destPath[1024];

        snprintf(srcPath, sizeof(srcPath), "%s/%s", source_filename, entry->d_name);
        snprintf(destPath, sizeof(destPath), "%s/%s", dest_filename, entry->d_name);

        if (stat(srcPath, &st) == -1) {
            fprintf(stderr, "Error: Could not stat '%s'\n", srcPath);
            result = -1;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (encrypt_folder(srcPath, destPath, key) != 0) {
                result = -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            printf("Encrypting file: %s -> %s\n", srcPath, destPath);
            if (encrypt_file(srcPath, destPath, key) != 0) {
                result = -1;
            }
        }
    }

    closedir(dir);
    return result;
}

int encrypt_literal(const char* literal, const uint32_t* key) {

    size_t bytes = slen(literal);

    printf("key:\n");
    for (int i = 0; i < KEY_LENGTH; ++i) {
        printf("%02x", *(key+i));
    }
    printf("\n\n");

    uint8_t* data = aes_256_encrypt((uint8_t*)literal, bytes, key);
    if (data == NULL) return 1;

    printf("Data:\n");
    for (int i = 0; i < bytes + 12; ++i) {
        printf("%02x", *(data + i));
    }
    printf("\n");

    free(data);
    return 0;
}

int main(int argc, char** argv) {

    int opt;
    char *source_filename = NULL, *destination_filename = NULL, *literal = NULL;
    uint32_t* secret_key = NULL;
    uint8_t isFile = 0, isLiteral = 0, isFolder = 0, genKey = 0;
    struct stat stats;

    while ((opt = getopt(argc, argv, ":r:f:d:gk:p:l:h")) != -1) {
        switch (opt) {
            case 'r':
                if (isFile || isLiteral) {
                    fprintf(stderr, "Option -r cannot be combined with option -f or -l.\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }


                source_filename = (char*) malloc(sizeof(char) * slen(optarg));
                scopy(optarg, source_filename);


                if (stat(source_filename, &stats) == -1) {
                    fprintf(stderr, "Cannot access %s, it likely does not exist.\n", source_filename);

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                if (!S_ISDIR(stats.st_mode)) {
                    fprintf(stderr, "%s is not a directory.\n", source_filename);

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                isFolder = 1;
                break;
            case 'f':
                if (isFolder || isLiteral) {
                    fprintf(stderr, "Option -f cannot be combined with option -r or -l.\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                source_filename = (char*) malloc(sizeof(char) * slen(optarg));
                scopy(optarg, source_filename);

                FILE* ptr = fopen(source_filename, "rb");
                if (ptr == NULL) {
                    fprintf(stderr, "Cannot access %s, it likely does not exist.\n", source_filename);
                    perror(NULL);

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                fclose(ptr);

                isFile = 1;
                break;
            case 'd':
                if (isLiteral) {
                    fprintf(stderr, "Option -d cannot be combined with option -l.\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                destination_filename = (char*) malloc(sizeof(char) * slen(optarg));
                scopy(optarg, destination_filename);
                break;
            case 'k':
                if (genKey) {
                    fprintf(stderr, "Incompatible options -p (provide key) -g (generate key) and -k (provide key literal)\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                sha256_init();
                sha256_insert((uint8_t*) optarg, slen(optarg) - 1);
                secret_key = sha256_finish();
                sha256_reset();
                break;
            case 'g':
                if (secret_key != NULL) {
                    fprintf(stderr, "Incompatible options -p (provide key) -g (generate key) and -k (provide key literal)\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                genKey = 1;
                break;
            case 'p':
                //provide key
                {

                    if (secret_key != NULL) {
                        fprintf(stderr, "Incompatible options -p (provide key) -g (generate key) and -k (provide key literal)\n");

                        freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                        return 1;
                    }

                    uint8_t* key_buff = NULL;
                    size_t key_len = 0;
                    if (read_file(optarg, &key_buff, &key_len)) {
                        fprintf("CRITICAL ERROR: failed while reading key %s\n", optarg);
                        freeAllNotNull(source_filename, destination_filename,literal, secret_key);
                        return 1;
                    }

                    if (key_len != 32) {
                        fprintf(stderr, "The key read from %s was not in the right format", optarg);
                        freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                        free(key_buff);
                        return 1;
                    }

                    secret_key = (uint32_t*) malloc(KEY_LENGTH * sizeof(uint32_t));
                    __builtin_memcpy(secret_key, key_buff, KEY_LENGTH * sizeof(uint32_t));
                    free(key_buff);
                }
                break;
            case 'h':
                printf("%s\n", HELP_STRING);
                return 0;
            case 'l':
                if (isFile || isFolder) {
                    fprintf(stderr, "Option -l cannot be combined with option -r or -f.\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }
                if (destination_filename != NULL) {
                    fprintf(stderr, "an encrypted literal will always be printed on the console (hint use > to pipe the output of this into a file with bash)\n");

                    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                    return 1;
                }

                literal = (char*) malloc(sizeof(char) * slen(optarg));
                scopy(optarg, literal);

                isLiteral = 1;
                break;
            case ':':
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);

                freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                return 1;
            case '?':
                fprintf(stderr, "Unknown option: -%c\n", optopt);

                freeAllNotNull(source_filename, destination_filename, literal, secret_key);
                return 1;
        }
    }

    if (destination_filename == NULL && (isFile || isFolder)) {
        const char* name = isFile ? "encrypted_file" : "encrypted_folder";
        destination_filename = (char*) malloc(sizeof(char) * slen(name));
        scopy(name, destination_filename);
    }

    if (genKey) {
        uint8_t buff[16];
        getentropy(buff, 16);

        sha256_init();
        sha256_insert(buff, 16);
        secret_key = sha256_finish();
        sha256_reset();
    }

    if (isLiteral) {
        if (encrypt_literal(literal, secret_key)) {
            freeAllNotNull(source_filename, destination_filename, literal, secret_key);
            return 1;
        }
    }
    if (isFile) {
        if (encrypt_file(source_filename, destination_filename, secret_key)) {
            freeAllNotNull(source_filename, destination_filename, literal, secret_key);
            return 1;
        }

        write_file("key.secret", (uint8_t*)secret_key, KEY_LENGTH * 4);
    }
    if (isFolder) {
        if (encrypt_folder(source_filename, destination_filename, secret_key)) {
            freeAllNotNull(source_filename, destination_filename, literal, secret_key);
            return 1;
        }
        write_file("key.secret", (uint8_t*)secret_key, KEY_LENGTH * 4);
    }

    freeAllNotNull(source_filename, destination_filename, literal, secret_key);
    return 0;
}