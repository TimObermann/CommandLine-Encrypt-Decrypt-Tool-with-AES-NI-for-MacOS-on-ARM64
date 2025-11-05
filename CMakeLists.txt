cmake_minimum_required(VERSION 4.0)
project(encryptCliTool)

set(CMAKE_CXX_STANDARD 20)
add_compile_options(-march=armv8-a+crypto)

add_library(cryptutil STATIC
    src/AES_with_NI.c
    src/sha256.c
    src/util.c
)

target_include_directories(cryptutil PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(encrypt
    encrypt/encrypt_cli.c
)

target_link_libraries(encrypt PRIVATE cryptutil)

add_executable(decrypt
        decrypt/decrypt_cli.c
)

target_link_libraries(decrypt PRIVATE cryptutil)
