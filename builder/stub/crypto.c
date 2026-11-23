/* builder/stub/crypto.c */
#include "crypto.h"
#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")

static int gcm_run(int encrypt, const unsigned char *key32,
                   const unsigned char iv[12],
                   const unsigned char *in, size_t in_len,
                   unsigned char *out, size_t *out_len,
                   unsigned char tag[16]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;
    int ok = -1;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) < 0) return -1;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) < 0) goto done;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key32, 32, 0) < 0) goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv;
    info.cbNonce = 12;
    info.pbTag   = tag;
    info.cbTag   = 16;

    ULONG written = 0;
    if (encrypt) {
        st = BCryptEncrypt(hKey, (PUCHAR)in, (ULONG)in_len, &info,
                           NULL, 0, out, (ULONG)*out_len, &written, 0);
    } else {
        st = BCryptDecrypt(hKey, (PUCHAR)in, (ULONG)in_len, &info,
                           NULL, 0, out, (ULONG)*out_len, &written, 0);
    }
    if (st >= 0) { *out_len = written; ok = 0; }

done:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

int crypto_init(crypto_ctx *c, const unsigned char *key32) {
    memcpy(c->key, key32, 32);
    return BCryptGenRandom(NULL, c->iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0 ? 0 : -1;
}

int crypto_seal(crypto_ctx *c, const unsigned char *pt, size_t pt_len,
                unsigned char *ct, size_t *ct_len,
                unsigned char tag[16], unsigned char iv_out[12]) {
    BCryptGenRandom(NULL, c->iv, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    memcpy(iv_out, c->iv, 12);
    return gcm_run(1, c->key, c->iv, pt, pt_len, ct, ct_len, tag);
}

int crypto_open(crypto_ctx *c, const unsigned char iv[12],
                const unsigned char *ct, size_t ct_len,
                const unsigned char tag[16],
                unsigned char *pt, size_t *pt_len) {
    return gcm_run(0, c->key, iv, ct, ct_len, pt, pt_len, (unsigned char*)tag);
}
