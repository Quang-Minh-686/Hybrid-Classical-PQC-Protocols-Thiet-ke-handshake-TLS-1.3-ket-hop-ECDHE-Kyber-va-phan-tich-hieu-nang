#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>   
#include "oqs_hybrid_groups.h"

static OSSL_PROVIDER *g_oqs_provider  = NULL;
static OSSL_PROVIDER *g_base_provider = NULL;

int oqs_provider_init(void)
{
    g_base_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!g_base_provider) {
        fprintf(stderr, "[oqs] Không load được default provider\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    g_oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (!g_oqs_provider) {
        fprintf(stderr, "[oqs] Không load được oqs-provider. "
                        "Kiểm tra OQS_PROVIDER_PATH hoặc openssl.cnf\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}

void oqs_provider_cleanup(void)
{
    OSSL_PROVIDER_unload(g_oqs_provider);
    OSSL_PROVIDER_unload(g_base_provider);
    g_oqs_provider = g_base_provider = NULL;
}

int oqs_is_hybrid_group(SSL *ssl)
{
    int group_id = SSL_get_negotiated_group(ssl);
    if (group_id <= 0)
        return 0;   

    const char *name = SSL_group_to_name(ssl, group_id);
    if (!name)
        return 0;

    const char *hybrid_groups[] = {
        OQS_GROUP_X25519_MLKEM512,
        OQS_GROUP_P256_MLKEM512,
        OQS_GROUP_P384_MLKEM768,
        OQS_GROUP_P521_MLKEM1024,
        NULL
    };

    for (int i = 0; hybrid_groups[i] != NULL; i++) {
        if (strcmp(name, hybrid_groups[i]) == 0)
            return 1;
    }
    return 0;
}

int oqs_configure_groups(SSL_CTX *ctx)
{
    if (SSL_CTX_set1_groups_list(ctx, HYBRID_GROUPS_LIST) != 1) {
        fprintf(stderr, "[oqs] SSL_CTX_set1_groups_list thất bại. "
                        "oqs-provider đã được load chưa?\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    return 1;
}

void oqs_hybrid_fallback_info_cb(const SSL *ssl, int where, int ret)
{
    (void)ret;

    if (!(where & SSL_CB_HANDSHAKE_DONE))
        return;

    int group_id = SSL_get_negotiated_group((SSL *)ssl);
    const char *name = (group_id > 0)
                       ? SSL_group_to_name((SSL *)ssl, group_id)
                       : "(unknown)";

    if (oqs_is_hybrid_group((SSL *)ssl)) {
        fprintf(stderr, "[oqs] Handshake OK — hybrid group: %s\n", name);
    } else {
        fprintf(stderr, "[oqs] CẢNH BÁO: Peer không hỗ trợ ML-KEM hybrid. "
                        "Fallback sang classical group: %s\n", name);
    }
}
