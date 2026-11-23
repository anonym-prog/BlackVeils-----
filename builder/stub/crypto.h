/* builder/stub/crypto.h */
#ifndef CRYPTO_H
#define CRYPTO_H
#include <stddef.h>

typedef struct {
    unsigned char key[32];
    unsigned char iv[12];
} crypto_ctx;

int crypto_init(crypto_ctx *c, const unsigned char *key32);
int crypto_seal(crypto_ctx *c, const unsigned char *pt, size_t pt_len,
                unsigned char *ct, size_t *ct_len,
                unsigned char tag[16], unsigned char iv_out[12]);
int crypto_open(crypto_ctx *c, const unsigned char iv[12],
                const unsigned char *ct, size_t ct_len,
                const unsigned char tag[16],
                unsigned char *pt, size_t *pt_len);
#endif
