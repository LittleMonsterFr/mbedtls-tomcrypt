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

add_library(crypto ${MBEDTLS_SRC} ${LIBTOMMATH_SRC} ${LIBTOMCRYPT_SRC})

# Add compile flags for this build only
target_compile_definitions(crypto PUBLIC
        LTC_SOURCE
        LTC_NO_RSA_BLINDING
        LTM_DESC
        )


include_directories(crypto PUBLIC mbedtls/include)
include_directories(crypto PUBLIC libtomcrypt/src/headers)
include_directories(crypto PUBLIC libtommath)
include_directories(crypto PUBLIC openssl/include)

set(bins
        test-rsa-sign-verify-mbedtls-libtomcrypt.c
        test-rsa-sign-verify-libtomcrypt-mbedtls.c
        test-rsa-sign-verify-libtomcrypt-openssl.c
        test-rsa-sign-verify-mbedtls-openssl.c
        )

foreach(bin ${bins})

    get_filename_component(bin_name ${bin} NAME_WE)

    add_executable(${bin_name} ${bin})

    target_link_libraries(${bin_name} crypto /home/littlemonster/chirp/mbedtls-tomcrypt/openssl/libcrypto.a pthread dl)

    # Specify the folder in which to put the executable
    set_target_properties(${bin_name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
            )

endforeach()

