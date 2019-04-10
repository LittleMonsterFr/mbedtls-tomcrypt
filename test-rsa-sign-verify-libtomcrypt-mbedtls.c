
#include <stdint.h>

#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "tomcrypt.h"

#define ERROR() printf("Error at line : %d\n", __LINE__);

char *data = "This is the data which will be hashed and then signed by RSA";

int main(void)
{
    printf("Generating signature with LIBTOMCRYPT :\n");

    crypt_mp_init("ltm");

    printf("* LibTomCrypt initialised\n");

    int hash_idx;
    if ((hash_idx = register_hash(&sha256_desc)) == -1)
    {
        ERROR()
        return 1;
    }

    printf("* Hash registered\n");

    FILE *f = fopen("private_key.der", "r");
    unsigned char PRIVATE_KEY[4096] = {0};
    size_t read = fread(PRIVATE_KEY, sizeof(unsigned char), 4096, f);
    fclose(f);

    int err;
    rsa_key pub_key;
    if ((err = rsa_import(PRIVATE_KEY, read, &pub_key)) != CRYPT_OK)
    {
        ERROR()
        printf("%s\n", error_to_string(err));
        return err;
    }

    printf("* Private key parsed\n");

    int32_t prng_idx;
    if ((prng_idx = register_prng(&sprng_desc)) == -1)
    {
        ERROR()
        rsa_free(&pub_key);
        return -1;
    }

    printf("* Random number generator registered\n");

    size_t data_length = strlen(data);
    unsigned long signature_length = 256;
    unsigned char *signature = calloc(signature_length, sizeof(unsigned char));

    err = rsa_sign_hash((const unsigned char *) data, data_length,
                        signature, &signature_length,
                        NULL, prng_idx, hash_idx, 12,
                        &pub_key);

    if (err != CRYPT_OK)
    {
        ERROR()
        rsa_free(&pub_key);
        free(signature);
        return err;
    }

    printf("* Data hashed and signature generated\n\n");

    rsa_free(&pub_key);

    printf("Verifying signature with MBEDTLS :\n");

    f = fopen("public_key.der", "r");
    unsigned char PUBLIC_KEY[4096] = {0};
    read = fread(PUBLIC_KEY, sizeof(unsigned char), 4096, f);
    fclose(f);

    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);

    if ((err = mbedtls_pk_parse_public_key(&pk_ctx, PUBLIC_KEY, read)) != 0)
    {
        ERROR()
        free(signature);
        return err;
    }

    printf("* Public key parsed\n");

    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    printf("* Padding set\n");

    const mbedtls_md_info_t *md_sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int hash_size = md_sha256_info->size;
    unsigned char *hash = calloc(hash_size, sizeof(unsigned char));

    if((err = mbedtls_md(md_sha256_info, (const unsigned char *) data, data_length, hash)) != 0)
    {
        ERROR()
        free(signature);
        free(hash);
        mbedtls_pk_free(&pk_ctx);
        return err;
    }

    printf("* Data hashed\n");

    err = mbedtls_pk_verify(&pk_ctx, MBEDTLS_MD_SHA256, hash, hash_size, signature, signature_length);

    if (err != 0)
    {
        ERROR()
        char error[1024] = {0};
        mbedtls_strerror(err, error, 1024);
        printf("Error : %s\n", error);
        free(signature);
        free(hash);
        mbedtls_pk_free(&pk_ctx);
        return err;
    }

    printf("* Hash signed\n\n");


    mbedtls_pk_free(&pk_ctx);
    free(hash);

    free(signature);

    printf("* Leaving program\n");
    return 0;
}