// FIXME: sprintf->snprintf everywhere.
// FIXME: support null characters in responses.

#include "http.h"
#include "debug.h"
#include "uns.h"

#include <osapi.h>
#include <user_interface.h>
#include <espconn.h>
#include <mem.h>
#include <limits.h>


// Internal state.
typedef struct {
    char *verb;
    char *path;
    int port;
    char *form_data;
    char *headers;
    char *hostname;
    char *buffer;
    int buffer_size;
    http_callback user_callback;
    void *arg;
    bool tls;
} httprequest;


static ICACHE_FLASH_ATTR
char * esp_strdup(const char * str) {
    if (str == NULL) {
        return NULL;
    }
    // +1 for null character
    char * new_str = (char *)os_malloc(os_strlen(str) + 1); 
    if (new_str == NULL) {
        os_printf("esp_strdup: malloc error");
        return NULL;
    }
    os_strcpy(new_str, str);
    return new_str;
}

static ICACHE_FLASH_ATTR
int esp_isupper(char c) {
    return (c >= 'A' && c <= 'Z');
}

static ICACHE_FLASH_ATTR
int esp_isalpha(char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}


static ICACHE_FLASH_ATTR
int esp_isspace(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static ICACHE_FLASH_ATTR
int esp_isdigit(char c) {
    return (c >= '0' && c <= '9');
}

/*
 * Convert a string to a long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
ICACHE_FLASH_ATTR
long esp_strtol(const char *nptr, char **endptr, int base) {
    os_printf("-----esp_strtol----\r\n");
    const char *s = nptr;
    unsigned long acc;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    /*
     * Skip white space and pick up leading +/- sign if any.
     * If base is 0, allow 0x for hex and 0 for octal, else
     * assume decimal; if base is already 16, allow 0x.
     */
    do {
        c = *s++;
    } while (esp_isspace(c));
    if (c == '-') {
        neg = 1;
        c = *s++;
    } else if (c == '+')
        c = *s++;
    if ((base == 0 || base == 16) &&
        c == '0' && (*s == 'x' || *s == 'X')) {
        c = s[1];
        s += 2;
        base = 16;
    } else if ((base == 0 || base == 2) &&
        c == '0' && (*s == 'b' || *s == 'B')) {
        c = s[1];
        s += 2;
        base = 2;
    }
    if (base == 0)
        base = c == '0' ? 8 : 10;

    /*
     * Compute the cutoff value between legal numbers and illegal
     * numbers.  That is the largest legal value, divided by the
     * base.  An input number that is greater than this value, if
     * followed by a legal input character, is too big.  One that
     * is equal to this value may be valid or not; the limit
     * between valid and invalid numbers is then based on the last
     * digit.  For instance, if the range for longs is
     * [-2147483648..2147483647] and the input base is 10,
     * cutoff will be set to 214748364 and cutlim to either
     * 7 (neg==0) or 8 (neg==1), meaning that if we have accumulated
     * a value > 214748364, or equal but the next digit is > 7 (or 8),
     * the number is too big, and we will return a range error.
     *
     * Set any if any `digits' consumed; make it negative to indicate
     * overflow.
     */
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0;; c = *s++) {
        if (esp_isdigit(c))
            c -= '0';
        else if (esp_isalpha(c))
            c -= esp_isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
        if (c >= base)
            break;
        if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
//      errno = ERANGE;
    } else if (neg)
        acc = -acc;
    if (endptr != 0)
        *endptr = (char *)(any ? s - 1 : nptr);
    return (acc);
}


static ICACHE_FLASH_ATTR 
int chunked_decode(const char *chunked, char *decode) {

    int i = 0, j = 0;
    int decode_size = 0;
    char *str = (char *)chunked;
    do
    {
        char * endstr = NULL;
        //[chunk-size]
        i = esp_strtol(str + j, &endstr, 16);
        if (i <= 0) 
            break;
        //[chunk-size-end-ptr]
        endstr = (char *)os_strstr(str + j, "\r\n");
        //[chunk-ext]
        j += endstr - (str + j);
        //[CRLF]
        j += 2;
        //[chunk-data]
        decode_size += i;
        os_memcpy((char *)&decode[decode_size - i], (char *)str + j, i);
        j += i;
        //[CRLF]
        j += 2;
    } while(true);

    //
    //footer CRLF
    //

    return j;
}

static ICACHE_FLASH_ATTR 
void receive_callback(void * arg, char * buf, unsigned short len) {

    struct espconn * conn = (struct espconn *)arg;
    httprequest * req = (httprequest *)conn->reverse;

    if (req->buffer == NULL) {
        return;
    }

    // Let's do the equivalent of a realloc().
    const int new_size = req->buffer_size + len;
    char * new_buffer;
    if ((new_size > BUFFER_SIZE_MAX) || 
            (NULL == (new_buffer = (char *)os_malloc(new_size)))) {
        os_printf("Response too long (%d)\n", new_size);
        // Discard the buffer to avoid using an incomplete response.
        req->buffer[0] = '\0';
#if TLS_ENABLED
        if (req->tls)
            espconn_secure_disconnect(conn);
        else
#endif
            espconn_disconnect(conn);

        return; // The disconnect callback will be called.
    }

    os_memcpy(new_buffer, req->buffer, req->buffer_size);
    // Append new data.
    os_memcpy(new_buffer + req->buffer_size - 1 , buf, len);
    new_buffer[new_size - 1] = '\0'; // Make sure there is an end of string.

    os_free(req->buffer);
    req->buffer = new_buffer;
    req->buffer_size = new_size;
    DEBUG("%s\n", req->buffer);
    
    char *contentlength_header = (char *)os_strstr(req->buffer, 
          "Content-Length");
    uint16_t contentlength;
    if (contentlength_header) {
        contentlength = atoi(contentlength_header);
        DEBUG("Content-Length: %d\n", contentlength);
        if (contentlength == 0) {
#if TLS_ENABLED
            if (req->tls)
                 espconn_secure_disconnect(conn);
#endif
            else
                 espconn_disconnect(conn);
        }
    }
}


static ICACHE_FLASH_ATTR 
void sent_callback(void * arg) {

    struct espconn * conn = (struct espconn *)arg;
    httprequest * req = (httprequest *)conn->reverse;

    if (req->form_data == NULL) {
        INFO("HTTP form sent\n");
    }
    else {
        // The headers were sent, now send the contents.
        DEBUG("Sending request body\n");
#if TLS_ENABLED
        if (req->tls)
            espconn_secure_sent(conn, (uint8_t *)req->form_data, 
                    strlen(req->form_data));
        else
#endif
            espconn_sent(conn, (uint8_t *)req->form_data, 
                    strlen(req->form_data));
        os_free(req->form_data);
        req->form_data = NULL;
    }
}


static ICACHE_FLASH_ATTR 
void connect_callback(void * arg) {
    struct espconn * conn = (struct espconn *)arg;
    httprequest * req = (httprequest *)conn->reverse;

    espconn_regist_recvcb(conn, receive_callback);
    espconn_regist_sentcb(conn, sent_callback);

    const char * method = req->verb;
    char form_headers[32] = "";

    if (req->form_data != NULL) { // If there is data this is a POST request.
        os_sprintf(form_headers, "Content-Length: %d\r\n", 
                strlen(req->form_data));
    }

    char buf[
        69 + 
        strlen(method) + 
        strlen(req->path) + 
        strlen(req->hostname) +
        strlen(req->headers) + 
        strlen(form_headers)
    ];
    int len = os_sprintf(
            buf,
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Connection: close\r\n"
            "User-Agent: ESP8266\r\n"
            "%s"
            "%s"
            "\r\n",
            method, req->path, req->hostname, req->port, req->headers, 
            form_headers);

#ifdef TLS_ENABLED
    if (req->tls)
        espconn_secure_send(conn, (uint8_t *)buf, len);
    else
#endif
        espconn_sent(conn, (uint8_t *)buf, len);

    //os_printf("send http data %d : \n%s \r\n",len,buf);
    os_free(req->headers);
    req->headers = NULL;
    DEBUG("Sending request header\n");
}


static void ICACHE_FLASH_ATTR 
disconnect_callback(void * arg) {
    DEBUG("Disconnected\n");
    struct espconn *conn = (struct espconn *)arg;

    if(conn == NULL) {
        return;
    }

    if(conn->reverse != NULL) {
        httprequest * req = (httprequest *)conn->reverse;
        int http_status = -1;
        char * body = "";
        if (req->buffer == NULL) {
            os_printf("Buffer shouldn't be NULL\n");
        }
        else if (req->buffer[0] != '\0') {
            // FIXME: make sure this is not a partial response, using the 
            // Content-Length header.

            const char * version = "HTTP/1.1 ";
            if (os_strncmp(req->buffer, version, strlen(version)) != 0) {
                os_printf("Invalid version in %s\n", req->buffer);
            }
            else {
                http_status = atoi(req->buffer + strlen(version));
                body = (char *)os_strstr(req->buffer, "\r\n\r\n") + 4;
                if(os_strstr(req->buffer, "Transfer-Encoding: chunked"))
                {
                    int body_size = req->buffer_size - (body - req->buffer);
                    char chunked_decode_buffer[body_size];
                    os_memset(chunked_decode_buffer, 0, body_size);
                    // Chunked data
                    chunked_decode(body, chunked_decode_buffer);
                    os_memcpy(body, chunked_decode_buffer, body_size);
                }
            }
        }

        if (req->user_callback != NULL) { // Callback is optional.
            req->user_callback(http_status, body, req->arg);
        }

        os_free(req->buffer);
        os_free(req->hostname);
        os_free(req->verb);
        os_free(req->path);
        os_free(req);
    }

    espconn_delete(conn);

    if(conn->proto.tcp != NULL) {
        os_free(conn->proto.tcp);
    }
    os_free(conn);
}


static ICACHE_FLASH_ATTR 
void error_callback(void *arg, int8_t errType) {
    DEBUG("Disconnected with error: %d\n", errType);
    disconnect_callback(arg);
}


static ICACHE_FLASH_ATTR 
void http_connect(httprequest *req, ip_addr_t *addr) {
    struct espconn *conn = os_malloc(sizeof(struct espconn));
    espconn_set_opt(conn, ESPCONN_NODELAY);
    conn->type = ESPCONN_TCP;
    conn->state = ESPCONN_NONE;
    conn->proto.tcp = (esp_tcp *)os_malloc(sizeof(esp_tcp));
    conn->proto.tcp->local_port = espconn_port();
    conn->proto.tcp->remote_port = req->port;
    conn->reverse = req;
    
    os_memcpy(conn->proto.tcp->remote_ip, addr, 4);
    
    espconn_regist_connectcb(conn, connect_callback);
    espconn_regist_disconcb(conn, disconnect_callback);
    espconn_regist_reconcb(conn, error_callback);
  
#ifdef TLS_ENABLED
    if (req->tls) {
        if (!espconn_secure_ca_enable(TLS_LEVEL_CLIENT, TLS_CA_CRT_SECTOR)) {
            ERROR("TLS CA Activation failed");
            disconnect_callback(conn);
            return;
        }
        ERROR("TLS CA Activation success");
        espconn_secure_connect(conn);
    }
    else 
#endif 
    {
        espconn_connect(conn);
    }
    
}


static ICACHE_FLASH_ATTR 
void dns_callback(const char *hostname, ip_addr_t *addr, void *arg) {
    //TODO: rename to requestargs
    httprequest *req = (httprequest *)arg;

    if (addr == NULL) {
        os_printf("DNS failed for %s\n", hostname);
        if (req->user_callback != NULL) {
            // TODO: Rename to cb or callback
            req->user_callback(-1, NULL, NULL);
        }
        os_free(req->buffer);
        os_free(req->hostname);
        os_free(req->verb);
        os_free(req->path);
        os_free(req);
    }
    else {
        DEBUG("DNS found %s " IPSTR "\n", hostname, IP2STR(addr));
        http_connect(req, addr);
    }
}


static ICACHE_FLASH_ATTR 
httprequest * create_request(const char *hostname, const char *verb, 
        const char *path, const char *headers, const char * body, 
        bool tls, http_callback cb, void *arg) {

    httprequest *req = (httprequest *)os_malloc(sizeof(httprequest));
    req->hostname = esp_strdup(hostname);
    req->verb = esp_strdup(verb);
    req->path = esp_strdup(path);
    req->port = tls? 443: 80;
    req->headers = esp_strdup(headers);
    req->form_data = esp_strdup(body);
    req->buffer_size = 1;
    req->buffer = (char *)os_malloc(1);
    req->buffer[0] = '\0'; // Empty string.
    req->user_callback = cb;
    req->arg = arg;
    req->tls = tls;
     
    return req;
}


ICACHE_FLASH_ATTR 
void http_send_request(const char * hostname, const char *verb, 
        const char * path, const char *headers, const char * body, bool tls, 
        http_callback cb, void *arg) {

    httprequest *req = create_request(hostname, verb, path, headers, body,
            tls, cb, arg);

    DEBUG("DNS request\n");
    ip_addr_t addr;
    // It seems we don't need a real espconn pointer here.
    err_t error = espconn_gethostbyname((struct espconn *)req, hostname, 
            &addr, dns_callback);

    if (error == ESPCONN_INPROGRESS) {
        DEBUG("DNS pending\n");
    }
    else if (error == ESPCONN_OK) {
        // Already in the local names table (or hostname was an IP address), 
        // execute the callback ourselves.
        dns_callback(hostname, &addr, req);
    }
    else {
        if (error == ESPCONN_ARG) {
            os_printf("DNS arg error %s\n", hostname);
        }
        else {
            os_printf("DNS error code %d\n", error);
        }
        // Handle all DNS errors the same way.
        dns_callback(hostname, NULL, req); 
    }
}


static ICACHE_FLASH_ATTR 
void unscb(struct unsrecord *rec, void *arg) {
    httprequest *req = (httprequest *)arg;
    http_connect(req, &rec->address);
}


ICACHE_FLASH_ATTR 
void http_send_request_uns(const char *hostname, const char *verb, 
        const char * path, const char *headers, const char * body, bool tls, 
        http_callback cb, void *arg) {
    httprequest *req = create_request(hostname, verb, path, headers, body,
            tls, cb, arg);
    uns_discover(req->hostname, unscb, req);
}
