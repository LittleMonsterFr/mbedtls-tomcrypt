#define LTC_TO_MBEDTLS 1
#define MBEDTLS_TO_LTC 0

#include <stdint.h>

#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "tomcrypt.h"

#define ERROR() printf("Error at line : %d\n", __LINE__);

char *data = "This is the data which will be hashed and then signed by RSA";

#if LTC_TO_MBEDTLS == 1
int main(void)
{
    printf("Generating signature with LIBTOMCRYPT :\n");

    init_LTM();

    printf("* LibTomCrypt initialised\n");

    int hash_idx;
    if ((hash_idx = register_hash(&sha256_desc)) == -1)
    {
        ERROR();
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
        ERROR();
        printf("%s\n", error_to_string(err));
        return err;
    }

    printf("* Private key parsed\n");

    int32_t prng_idx;
    if ((prng_idx = register_prng(&sprng_desc)) == -1)
    {
        ERROR();
        mp_clear_multi(pub_key.d, pub_key.e, pub_key.N, pub_key.dQ, pub_key.dP,
                       pub_key.qP, pub_key.p, pub_key.q, NULL);
        return -1;
    }

    printf("* Random number generator registered\n");

    size_t data_length = strlen(data);
    unsigned long signature_length = 256;
    unsigned char *signature = calloc(signature_length, sizeof(unsigned char));

    err = rsa_sign_hash(data, data_length,
                        signature, &signature_length,
                        NULL, prng_idx, hash_idx, 12,
                        &pub_key);

    if (err != CRYPT_OK)
    {
        ERROR();
        free(signature);
        return err;
    }

    printf("* Data hashed and signature generated\n\n");

    mp_clear_multi(pub_key.d, pub_key.e, pub_key.N, pub_key.dQ, pub_key.dP,
                   pub_key.qP,pub_key.p, pub_key.q, NULL);

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

    if((err = mbedtls_md(md_sha256_info, data, data_length, hash)) != 0)
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
        ERROR();
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

#else

int main(void)
{
    printf("Generating signature with MBEDTLS :\n");

    FILE *f = fopen("/Users/littlemonster/chirp/chirp-c-sdk-core/private_key.der", "r");
    unsigned char PRIVATE_KEY[4096] = {0};
    size_t read = fread(PRIVATE_KEY, sizeof(unsigned char), 4096, f);
    fclose(f);

    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);
    int err;

    if ((err = mbedtls_pk_parse_key(&pk_ctx, PRIVATE_KEY, read, NULL, 0)) != 0)
    {
        ERROR()
        return err;
    }

    printf("* Private key parsed\n");

    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk_ctx), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    printf("* Padding set\n");

    mbedtls_entropy_context entropy_ctx;
    mbedtls_ctr_drbg_context ctr_drbg_ctx;

    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg_ctx);

    if ((err = mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0)) != 0)
    {
        ERROR()
        mbedtls_pk_free(&pk_ctx);
        return err;
    }

    printf("* Random number generator seeded\n");

    const mbedtls_md_info_t *md_sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int hash_size = md_sha256_info->size;
    size_t data_length = strlen(data);
    unsigned char *hash = calloc(hash_size, sizeof(unsigned char));

    if((err = mbedtls_md(md_sha256_info, data, data_length, hash)) != 0)
    {
        ERROR()
        mbedtls_pk_free(&pk_ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
        mbedtls_entropy_free(&entropy_ctx);
        free(hash);
        return err;
    }

    printf("* Data hashed\n");

    unsigned long signature_length = 256;
    unsigned char *signature = calloc(signature_length, sizeof(unsigned char));

    if ((err = mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, hash, 0,
                               signature, &signature_length,
                               mbedtls_ctr_drbg_random, &ctr_drbg_ctx)) != 0)
    {
        ERROR()
        mbedtls_pk_free(&pk_ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
        mbedtls_entropy_free(&entropy_ctx);
        free(hash);
        free(signature);
        return err;
    }

    printf("* Hash signed\n\n");

    mbedtls_pk_free(&pk_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
    mbedtls_entropy_free(&entropy_ctx);
    free(hash);

    printf("Verifying signature with LIBTOMCRYPT :\n");

    init_LTM();

    printf("* LibTomCrypt initialised\n");

    int hash_idx;
    if ((hash_idx = register_hash(&sha256_desc)) == -1)
    {
        ERROR();
        return 1;
    }

    printf("* Hash registered\n");

    f = fopen("/Users/littlemonster/chirp/chirp-c-sdk-core/public_key.der", "r");
    unsigned char PUBLIC_KEY[4096] = {0};
    read = fread(PUBLIC_KEY, sizeof(unsigned char), 4096, f);
    fclose(f);

    rsa_key pub_key;
    if ((err = rsa_import(PUBLIC_KEY, read, &pub_key)) != CRYPT_OK)
    {
        ERROR()
        free(signature);
        return err;
    }

    printf("* Public key parsed\n");

    int stat;
    err = rsa_verify_hash(signature, signature_length,
                                  data, data_length,
                                  hash_idx, hash_descriptor[hash_idx].hashsize, &stat, &pub_key);

    if(err != CRYPT_OK)
    {
        ERROR()
        return err;
    }

    printf("* Data hashed and signature verified\n\n");

    mp_clear_multi(pub_key.d, pub_key.e, pub_key.N, pub_key.dQ, pub_key.dP,
                   pub_key.qP, pub_key.p, pub_key.q, NULL);

    free(signature);

    printf("Leaving program\n");
    return 0;
}

#endif


