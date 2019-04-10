
#include <stdint.h>

#include "tomcrypt.h"

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/rsa.h"

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
    rsa_key private_key;
    if ((err = rsa_import(PRIVATE_KEY, read, &private_key)) != CRYPT_OK)
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
        rsa_free(&private_key);
        return -1;
    }

    printf("* Random number generator registered\n");

    size_t data_length = strlen(data);
    unsigned long signature_length = 256;
    unsigned char *signature = calloc(signature_length, sizeof(unsigned char));

    err = rsa_sign_hash((const unsigned char *) data, data_length,
                        signature, &signature_length,
                        NULL, prng_idx, hash_idx, 12,
                        &private_key);

    if (err != CRYPT_OK)
    {
        ERROR()
        rsa_free(&private_key);
        free(signature);
        return err;
    }

    printf("* Data hashed and signature generated\n\n");

    rsa_free(&private_key);

    printf("Verifying signature with OPENSSL :\n");

    f = fopen("public_key.pem", "r");

    EVP_PKEY *PUBLIC_KEY = EVP_PKEY_new();
    PEM_read_PUBKEY(f, &PUBLIC_KEY, NULL, NULL);
    fclose(f);

    printf("* Public key parsed\n");

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    EVP_PKEY_CTX *pkeyCtx;
    if (EVP_DigestVerifyInit(ctx, &pkeyCtx, EVP_sha256(), NULL, PUBLIC_KEY) != 1)
    {
        ERROR()
        EVP_PKEY_free(PUBLIC_KEY);
        EVP_MD_CTX_destroy(ctx);
        free(signature);
        ERR_print_errors_fp(stdout);
        return -1;
    }

    printf("* Digest verified\n");

    EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING);

    printf("* Padding set\n");

    if (EVP_DigestVerifyUpdate(ctx, data, data_length) != 1)
    {
        ERROR()
        EVP_PKEY_free(PUBLIC_KEY);
        EVP_MD_CTX_destroy(ctx);
        free(signature);
        ERR_print_errors_fp(stdout);
        return -1;
    }

    printf("* Digest verification updated\n");

    if (EVP_DigestVerifyFinal(ctx, signature, signature_length) != 1)
    {
        ERROR()
        EVP_PKEY_free(PUBLIC_KEY);
        EVP_MD_CTX_destroy(ctx);
        free(signature);
        ERR_print_errors_fp(stdout);
        return -1;
    }

    EVP_PKEY_free(PUBLIC_KEY);
    EVP_MD_CTX_destroy(ctx);
    free(signature);

    printf("* Signature verified\n");

    printf("* Leaving program\n");
    return 0;
}