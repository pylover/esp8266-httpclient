#ifndef HTTP_H
#define HTTP_H

#define BUFFER_SIZE_MAX   2000 


#if SPI_SIZE_MAP == 2
#define TLS_CA_CRT_SECTOR   TLS_CA_CRT_SECTOR_MAP2
#elif SPI_SIZE_MAP == 3
#define TLS_CA_CRT_SECTOR   TLS_CA_CRT_SECTOR_MAP3
#elif SPI_SIZE_MAP == 4
#define TLS_CA_CRT_SECTOR   TLS_CA_CRT_SECTOR_MAP4
#elif SPI_SIZE_MAP == 6
#define TLS_CA_CRT_SECTOR   TLS_CA_CRT_SECTOR_MAP6
#elif SPI_SIZE_MAP == 8
#define TLS_CA_CRT_SECTOR   TLS_CA_CRT_SECTOR_MAP8
#endif

#define TLS_LEVEL_CLIENT    0x1
#define TLS_LEVEL_SERVER    0x2
#define TLS_LEVEL_BOTH      0x3


#include <c_types.h>



typedef void (*http_callback)(int status, char* body, void *arg);

void http_send_request_uns(
        const char *host, 
        const char *verb, 
        const char *path, 
        const char *headers, 
        const char *body, 
        bool tls,
        http_callback user_callback,
        void *arg
    );


void http_send_request(
        const char *host, 
        const char *verb, 
        const char *path, 
        const char *headers, 
        const char *body, 
        bool tls,
        http_callback user_callback,
        void *arg
    );


/* uns */
#define https_send_uns(h, v, p, hdr, b, cb, a) \
    http_send_request_uns((h), (v), (p), (hdr), (b), true, (cb), (a));

#define http_send_uns(h, v, p, hdr, b, cb, a) \
    send_request_uns((h), (v), (p), (hdr), (b), false, (cb), (a));

#define http_nobody_uns(h, v, p, cb, a) \
    http_send_request_uns((h), (v), (p), "", "", false, (cb), (a))

/* dns */
#define https_get(h, p, hdr, b, cb, a) \
    http_send_request((h), "GET", (p), (hdr), (b), true, (cb), (a));

#define https_send(h, v, p, hdr, b, cb, a) \
    http_send_request((h), (v), (p), (hdr), (b), true, (cb), (a));

#define http_send(h, v, p, hdr, b, cb, a) \
    http_send_request((h), (v), (p), (hdr), (b), false, (cb), (a));

#define http_nobody(h, v, p, cb, a) \
    http_send_request((h), (v), (p), "", "", false, (cb), (a))

#endif
