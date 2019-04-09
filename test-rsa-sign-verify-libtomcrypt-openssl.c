
#include <stdint.h>

#include "tomcrypt.h"

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#define ERROR() printf("Error at line : %d\n", __LINE__);

char *data = "This is the data which will be hashed and then signed by RSA";

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
    rsa_key private_key;
    if ((err = rsa_import(PRIVATE_KEY, read, &private_key)) != CRYPT_OK)
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
        mp_clear_multi(private_key.d, private_key.e, private_key.N, private_key.dQ, private_key.dP,
                       private_key.qP, private_key.p, private_key.q, NULL);
        return -1;
    }

    printf("* Random number generator registered\n");

    size_t data_length = strlen(data);
    unsigned long signature_length = 256;
    unsigned char *signature = calloc(signature_length, sizeof(unsigned char));

    err = rsa_sign_hash(data, data_length,
                        signature, &signature_length,
                        NULL, prng_idx, hash_idx, 12,
                        &private_key);

    if (err != CRYPT_OK)
    {
        ERROR();
        free(signature);
        return err;
    }

    printf("* Data hashed and signature generated\n\n");

    mp_clear_multi(private_key.d, private_key.e, private_key.N, private_key.dQ, private_key.dP,
                   private_key.qP,private_key.p, private_key.q, NULL);



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