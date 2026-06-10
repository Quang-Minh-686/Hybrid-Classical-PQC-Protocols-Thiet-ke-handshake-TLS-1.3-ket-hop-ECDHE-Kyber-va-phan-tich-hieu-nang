#ifndef OQS_HYBRID_GROUPS_H
#define OQS_HYBRID_GROUPS_H

#include <openssl/ssl.h>


#define HYBRID_GROUP_X25519_MLKEM512    "x25519_mlkem512"   
#define HYBRID_GROUP_P256_MLKEM512      "p256_mlkem512"
#define HYBRID_GROUP_X448_MLKEM768      "x448_mlkem768"
#define HYBRID_GROUP_P384_MLKEM768      "p384_mlkem768"


#define FALLBACK_GROUP_X25519           "x25519"
#define FALLBACK_GROUP_P256             "prime256v1"


#define HYBRID_GROUPS_LIST \
    HYBRID_GROUP_X25519_MLKEM512 ":" \
    HYBRID_GROUP_P256_MLKEM512   ":" \
    FALLBACK_GROUP_X25519        ":" \
    FALLBACK_GROUP_P256


#define ECDHE_X25519_SECRET_LEN     32   /* x25519 shared secret    */
#define ECDHE_P256_SECRET_LEN       32   /* P-256 shared secret     */
#define MLKEM512_SECRET_LEN         32   /* ML-KEM-512 shared secret */
#define MLKEM768_SECRET_LEN         32   /* ML-KEM-768 shared secret */
#define HYBRID_MASTER_SECRET_LEN    32   


#define OQS_PROVIDER_NAME       "oqsprovider"
#define OQS_PROVIDER_PATH       "/mnt/d/hybrid-tls/deps/openssl/lib64/ossl-modules"

#endif 
