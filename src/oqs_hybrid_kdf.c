#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>   
#include <openssl/rand.h>     
#include <openssl/err.h>
#include "oqs_hybrid_groups.h"

#define ECDHE_X25519_SECRET_LEN  32
#define MLKEM512_SECRET_LEN      32   /* ML-KEM-512 shared secret = 32 bytes */
#define COMBINED_SECRET_LEN      (ECDHE_X25519_SECRET_LEN + MLKEM512_SECRET_LEN)
#define HKDF_OUTPUT_LEN          48   /* 384-bit output cho TLS 1.3 */


int oqs_hybrid_hkdf_extract(
    const unsigned char *ecdhe_secret,
    const unsigned char *mlkem_secret,
    const unsigned char *salt,
    size_t               salt_len,
    unsigned char       *out,
    size_t              *out_len)
{
    EVP_KDF        *kdf     = NULL;
    EVP_KDF_CTX    *kdf_ctx = NULL;
    int             ret     = 0;

    unsigned char combined[COMBINED_SECRET_LEN];
    memcpy(combined,                       ecdhe_secret, ECDHE_X25519_SECRET_LEN);
    memcpy(combined + ECDHE_X25519_SECRET_LEN, mlkem_secret, MLKEM512_SECRET_LEN);

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (!kdf_ctx) goto cleanup;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mode",   "EXTRACT_ONLY", 0),
        OSSL_PARAM_construct_utf8_string("digest", "SHA2-256",      0),
        OSSL_PARAM_construct_octet_string("key",  combined,  COMBINED_SECRET_LEN),
        salt
            ? OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len)
            : OSSL_PARAM_END,
        OSSL_PARAM_END
    };

    if (EVP_KDF_CTX_set_params(kdf_ctx, params) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_KDF_derive(kdf_ctx, out, *out_len, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    OPENSSL_cleanse(combined, sizeof(combined));
    return ret;
}

int oqs_hybrid_hkdf_expand(
    const unsigned char *prk,
    size_t               prk_len,
    const unsigned char *info,
    size_t               info_len,
    unsigned char       *out,
    size_t               out_len)
{
    EVP_KDF        *kdf     = NULL;
    EVP_KDF_CTX    *kdf_ctx = NULL;
    int             ret     = 0;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) goto cleanup;
    kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (!kdf_ctx) goto cleanup;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("mode",   "EXPAND_ONLY", 0),
        OSSL_PARAM_construct_utf8_string("digest", "SHA2-256",    0),
        OSSL_PARAM_construct_octet_string("key",  (void *)prk,  prk_len),
        OSSL_PARAM_construct_octet_string("info", (void *)info, info_len),
        OSSL_PARAM_END
    };

    if (EVP_KDF_CTX_set_params(kdf_ctx, params) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_KDF_derive(kdf_ctx, out, out_len, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    return ret;
}

int oqs_hybrid_derive_key(
    const unsigned char *ecdhe_secret,
    const unsigned char *mlkem_secret,
    const unsigned char *salt,   size_t salt_len,
    const unsigned char *info,   size_t info_len,
    unsigned char       *out,    size_t out_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    size_t        prk_len = sizeof(prk);

    if (!oqs_hybrid_hkdf_extract(ecdhe_secret, mlkem_secret,
                                  salt, salt_len,
                                  prk, &prk_len))
        return 0;

    return oqs_hybrid_hkdf_expand(prk, prk_len, info, info_len, out, out_len);
}
