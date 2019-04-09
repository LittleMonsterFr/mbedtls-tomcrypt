
#include <stdint.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/rsa.h"

#define ERROR() printf("Error at line : %d\n", __LINE__);

char *data = "This is the data which will be hashed and then signed by RSA";

int main(void)
{
    printf("Generating signature with MBEDTLS :\n");

    FILE *f = fopen("private_key.der", "r");
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

    printf("Verifying signature with OPENSSL :\n");

    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);

    printf("* OPENSSL initialised :\n");

    f = fopen("public_key.pem", "r");
    unsigned char PUBLIC_KEY[4096] = {0};
    read = fread(PUBLIC_KEY, sizeof(unsigned char), 4096, f);
    fclose(f);

    BIO *keybio;
    keybio = BIO_new_mem_buf((void*)PUBLIC_KEY, -1);
    if (keybio == NULL) {
        ERROR();
        return -1;
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

    printf("* Public key parsed\n");

    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    int ret = 0;
    EVP_PKEY_CTX *pkeyCtx;
    EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING);

    if(1 != EVP_DigestVerifyInit(m_RSAVerifyCtx, &pkeyCtx, EVP_sha256(),NULL,pubKey))
    {
        ERROR();
        return -1;
    }

    printf("* Hash initialised\n");

    if(1 != EVP_DigestVerifyUpdate(m_RSAVerifyCtx, data, data_length))
    {
        ERROR();
        return -1;
    }

    printf("* Data hashed\n");

    if(1 != EVP_DigestVerifyFinal(m_RSAVerifyCtx, signature, signature_length))
    {
        ERROR()
        return -1;
    }

    printf("* Signature verified\n");

    printf("* Leaving program\n");
    return 0;
}