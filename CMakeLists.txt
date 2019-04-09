# Specify the minimal CMake version supported
cmake_minimum_required(VERSION 3.13.0)

set(PROJECT_NAME mbedtls-tomcrypt)

# Name of the project and (optional) type of the project
project(${PROJECT_NAME} C)

# Sources for Mbedtls
set(MBEDTLS_SRC
        mbedtls/library/aes.c
        mbedtls/library/asn1parse.c
        mbedtls/library/asn1write.c
        mbedtls/library/base64.c
        mbedtls/library/bignum.c
        mbedtls/library/cipher.c
        mbedtls/library/cipher_wrap.c
        mbedtls/library/ctr_drbg.c
        mbedtls/library/entropy.c
        mbedtls/library/entropy_poll.c
        mbedtls/library/error.c
        mbedtls/library/md.c
        mbedtls/library/md_wrap.c
        mbedtls/library/oid.c
        mbedtls/library/pk.c
        mbedtls/library/pk_wrap.c
        mbedtls/library/pkparse.c
        mbedtls/library/platform_util.c
        mbedtls/library/rsa.c
        mbedtls/library/rsa_internal.c
        mbedtls/library/sha256.c
        mbedtls/library/version.c
        mbedtls/library/version_features.c
        )

# Sources for Libtommath.
FILE(GLOB LIBTOMMATH_SRC libtommath/*.c)

# Sources for Libtomcrypt. Naively recurse
FILE(GLOB_RECURSE LIBTOMCRYPT_SRC libtomcrypt/src/*.c)

add_executable(test-rsa-sign-verify test-rsa-sign-verify.c ${MBEDTLS_SRC} ${LIBTOMMATH_SRC} ${LIBTOMCRYPT_SRC})

target_include_directories(test-rsa-sign-verify PUBLIC mbedtls/include)
target_include_directories(test-rsa-sign-verify PUBLIC libtomcrypt/src/headers)
target_include_directories(test-rsa-sign-verify PUBLIC libtommath)

# Add compile flags for this build only
target_compile_definitions(test-rsa-sign-verify PUBLIC
        LTC_SOURCE
        LTC_NO_RSA_BLINDING
        LTM_DESC
        )

# Specify the folder in which to put the executable
set_target_properties(test-rsa-sign-verify PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
        )