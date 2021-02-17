#ifndef HTTP_H
#define HTTP_H

#define BUFFER_SIZE_MAX   2000 


typedef void (*http_callback)(int status, char* body, void *arg);

void http_send_uns(
        const char *host, 
        const char *verb, 
        const char *path, 
        const char *headers, 
        const char *body, 
        http_callback user_callback,
        void *arg
    );


void http_send(
        const char *host, 
        const char *verb, 
        const char *path, 
        const char *headers, 
        const char *body, 
        http_callback user_callback,
        void *arg
    );


#define http_nobody(h, v, p, cb, a) \
    http_send((h), (v), (p), "", "", (cb), (a))

#define http_nobody_uns(h, v, p, cb, a) \
    http_send_uns((h), (v), (p), "", "", (cb), (a))

#endif
