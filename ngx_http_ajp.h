
#ifndef NGX_HTTP_AJP_H
#define NGX_HTTP_AJP_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include "ngx_http_ajp_module.h"

#define AJP13_DEF_HOST "127.0.0.1"
#ifdef NETWARE
#define AJP13_DEF_PORT 9009     /* default to 9009 since 8009 is used by OS */
#else
#define AJP13_DEF_PORT 8009
#endif

#define AJP13_HTTPS_INDICATOR           "HTTPS"
#define AJP13_SSL_CLIENT_CERT_INDICATOR "SSL_CLIENT_CERT"
#define AJP13_SSL_CIPHER_INDICATOR      "SSL_CIPHER"
#define AJP13_SSL_SESSION_INDICATOR     "SSL_SESSION_ID"
#define AJP13_SSL_KEY_SIZE_INDICATOR    "SSL_CIPHER_USEKEYSIZE"


#define AJP_NULL_STRING_LENGTH (uint16_t)(-1)
#define AJP_EOVERFLOW          1001

typedef struct ajp_msg {
    ngx_buf_t  *buf;
    size_t      len;
    int         server_side;
} ajp_msg_t;

/*
 * Signature for the messages sent from Apache to tomcat
 */
#define AJP13_WS_HEADER             0x1234
#define AJP_HEADER_LEN              4
#define AJP_HEADER_SZ_LEN           2
#define AJP_HEADER_SZ               6
#define AJP_MSG_BUFFER_SZ           8192
#define AJP_MAX_BUFFER_SZ           65536
#define AJP13_MAX_SEND_BODY_SZ      (AJP_MAX_BUFFER_SZ - AJP_HEADER_SZ)
#define AJP_PING_PONG_SZ            128

/* Send a request from web server to container */
#define CMD_AJP13_FORWARD_REQUEST   (unsigned char)2

/* Write a body chunk from the servlet container to the web server */
#define CMD_AJP13_SEND_BODY_CHUNK   (unsigned char)3

/* Send response headers from the servlet container to the web server. */
#define CMD_AJP13_SEND_HEADERS      (unsigned char)4

/* Marks the end of response. */
#define CMD_AJP13_END_RESPONSE      (unsigned char)5

/*
 * Get further data from the web server if it hasn't all been
 * transferred yet.
 */
#define CMD_AJP13_GET_BODY_CHUNK    (unsigned char)6

/* The web server asks the container to shut itself down. */
#define CMD_AJP13_SHUTDOWN          (unsigned char)7

/* Webserver ask container to take control (logon phase) */
#define CMD_AJP13_PING              (unsigned char)8

/* Container response to cping request */
#define CMD_AJP13_CPONG             (unsigned char)9

/*
 * Webserver check if container is alive, since container should
 * respond by cpong
 */
#define CMD_AJP13_CPING             (unsigned char)10

/*
 * Conditional request attributes
 */
#define SC_A_CONTEXT            (unsigned char)1
#define SC_A_SERVLET_PATH       (unsigned char)2
#define SC_A_REMOTE_USER        (unsigned char)3
#define SC_A_AUTH_TYPE          (unsigned char)4
#define SC_A_QUERY_STRING       (unsigned char)5
#define SC_A_JVM_ROUTE          (unsigned char)6
#define SC_A_SSL_CERT           (unsigned char)7
#define SC_A_SSL_CIPHER         (unsigned char)8
#define SC_A_SSL_SESSION        (unsigned char)9
#define SC_A_REQ_ATTRIBUTE      (unsigned char)10
#define SC_A_SSL_KEY_SIZE       (unsigned char)11
#define SC_A_SECRET             (unsigned char)12
#define SC_A_ARE_DONE           (unsigned char)0xFF

/*
 * AJP private request attributes
 *
 * The following request attribute is recognized by Tomcat
 * to contain the forwarded remote port.
 */
#define SC_A_REQ_REMOTE_PORT    ("AJP_REMOTE_PORT")

/*
 * Request methods, coded as numbers instead of strings.
 * The list of methods was taken from Section 5.1.1 of RFC 2616,
 * RFC 2518, the ACL IETF draft, and the DeltaV IESG Proposed Standard.
 *          Method        = "OPTIONS"
 *                        | "GET"
 *                        | "HEAD"
 *                        | "POST"
 *                        | "PUT"
 *                        | "DELETE"
 *                        | "TRACE"
 *                        | "PROPFIND"
 *                        | "PROPPATCH"
 *                        | "MKCOL"
 *                        | "COPY"
 *                        | "MOVE"
 *                        | "LOCK"
 *                        | "UNLOCK"
 *                        | "ACL"
 *                        | "REPORT"
 *                        | "VERSION-CONTROL"
 *                        | "CHECKIN"
 *                        | "CHECKOUT"
 *                        | "UNCHECKOUT"
 *                        | "SEARCH"
 *                        | "MKWORKSPACE"
 *                        | "UPDATE"
 *                        | "LABEL"
 *                        | "MERGE"
 *                        | "BASELINE-CONTROL"
 *                        | "MKACTIVITY"
 *
 */
#define SC_M_OPTIONS            (unsigned char)1
#define SC_M_GET                (unsigned char)2
#define SC_M_HEAD               (unsigned char)3
#define SC_M_POST               (unsigned char)4
#define SC_M_PUT                (unsigned char)5
#define SC_M_DELETE             (unsigned char)6
#define SC_M_TRACE              (unsigned char)7
#define SC_M_PROPFIND           (unsigned char)8
#define SC_M_PROPPATCH          (unsigned char)9
#define SC_M_MKCOL              (unsigned char)10
#define SC_M_COPY               (unsigned char)11
#define SC_M_MOVE               (unsigned char)12
#define SC_M_LOCK               (unsigned char)13
#define SC_M_UNLOCK             (unsigned char)14

/* Not supported in Nginx */
#define SC_M_ACL                (unsigned char)15
#define SC_M_REPORT             (unsigned char)16
#define SC_M_VERSION_CONTROL    (unsigned char)17
#define SC_M_CHECKIN            (unsigned char)18
#define SC_M_CHECKOUT           (unsigned char)19
#define SC_M_UNCHECKOUT         (unsigned char)20
#define SC_M_SEARCH             (unsigned char)21
#define SC_M_MKWORKSPACE        (unsigned char)22
#define SC_M_UPDATE             (unsigned char)23
#define SC_M_LABEL              (unsigned char)24
#define SC_M_MERGE              (unsigned char)25
#define SC_M_BASELINE_CONTROL   (unsigned char)26
#define SC_M_MKACTIVITY         (unsigned char)27


/*
 * Frequent request headers, these headers are coded as numbers
 * instead of strings.
 *
 * Accept
 * Accept-Charset
 * Accept-Encoding
 * Accept-Language
 * Authorization
 * Connection
 * Content-Type
 * Content-Length
 * Cookie
 * Cookie2
 * Host
 * Pragma
 * Referer
 * User-Agent
 *
 */
#define SC_REQ_ACCEPT               (unsigned short)0xA001
#define SC_REQ_ACCEPT_CHARSET       (unsigned short)0xA002
#define SC_REQ_ACCEPT_ENCODING      (unsigned short)0xA003
#define SC_REQ_ACCEPT_LANGUAGE      (unsigned short)0xA004
#define SC_REQ_AUTHORIZATION        (unsigned short)0xA005
#define SC_REQ_CONNECTION           (unsigned short)0xA006
#define SC_REQ_CONTENT_TYPE         (unsigned short)0xA007
#define SC_REQ_CONTENT_LENGTH       (unsigned short)0xA008
#define SC_REQ_COOKIE               (unsigned short)0xA009
#define SC_REQ_COOKIE2              (unsigned short)0xA00A
#define SC_REQ_HOST                 (unsigned short)0xA00B
#define SC_REQ_PRAGMA               (unsigned short)0xA00C
#define SC_REQ_REFERER              (unsigned short)0xA00D
#define SC_REQ_USER_AGENT           (unsigned short)0xA00E

/*
 * Frequent response headers, these headers are coded as numbers
 * instead of strings.
 *
 * Content-Type
 * Content-Language
 * Content-Length
 * Date
 * Last-Modified
 * Location
 * Set-Cookie
 * Servlet-Engine
 * Status
 * WWW-Authenticate
 *
 */
#define SC_RESP_CONTENT_TYPE        (unsigned short)0xA001
#define SC_RESP_CONTENT_LANGUAGE    (unsigned short)0xA002
#define SC_RESP_CONTENT_LENGTH      (unsigned short)0xA003
#define SC_RESP_DATE                (unsigned short)0xA004
#define SC_RESP_LAST_MODIFIED       (unsigned short)0xA005
#define SC_RESP_LOCATION            (unsigned short)0xA006
#define SC_RESP_SET_COOKIE          (unsigned short)0xA007
#define SC_RESP_SET_COOKIE2         (unsigned short)0xA008
#define SC_RESP_SERVLET_ENGINE      (unsigned short)0xA009
#define SC_RESP_STATUS              (unsigned short)0xA00A
#define SC_RESP_WWW_AUTHENTICATE    (unsigned short)0xA00B

#define SC_RES_HEADERS_NUM          11

#define DUMP_LENGTH                 64

ngx_int_t ajp_msg_is_zero_length(u_char *head);

/*
 * Begin to parse an AJP Message, move the buffer header to the type's
 * position.
 *
 * @param msg       AJP Message to parse
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_parse_begin(ajp_msg_t *msg);

/*
 * Reset an AJP Message
 *
 * @param msg       AJP Message to reset
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_reset(ajp_msg_t *msg);

/*
 * Reuse an AJP Message
 *
 * @param msg       AJP Message to reuse
 * @return          The cleared message
 */
ajp_msg_t * ajp_msg_reuse(ajp_msg_t *msg);

/*
 * Mark the end of an AJP Message
 *
 * @param msg       AJP Message to end
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_end(ajp_msg_t *msg);

/*
 * Add an unsigned 32bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_uint32(ajp_msg_t *msg, uint32_t value);

/*
 * Add an unsigned 16bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_uint16(ajp_msg_t *msg, uint16_t value);

/*
 * Add an unsigned 8bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_uint8(ajp_msg_t *msg, u_char value);

/*
 *  Add a String in AJP message
 *
 * @param msg       AJP Message to get value from
 * @param value     Pointer to String
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_string(ajp_msg_t *msg, ngx_str_t *value);

/*
 * Get a 32bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_uint32(ajp_msg_t *msg, uint32_t *rvalue);

/*
 * Get a 16bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_uint16(ajp_msg_t *msg, uint16_t *rvalue);

/*
 * Peek a 16bits unsigned value from AJP Message, position in message
 * is not updated
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_peek_uint16(ajp_msg_t *msg, uint16_t *rvalue);

/*
 * Get a 8bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_uint8(ajp_msg_t *msg, u_char *rvalue);

/*
 * Peek a 8bits unsigned value from AJP Message, position in message
 * is not updated
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_peek_uint8(ajp_msg_t *msg, u_char *rvalue);

/*
 * Get a String value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_string(ajp_msg_t *msg, ngx_str_t *rvalue);


/*
 * Create an AJP Message from pool
 *
 * @param pool      memory pool to allocate AJP message from
 * @param size      size of the buffer to create
 * @param rmsg      Pointer to newly created AJP message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_create(ngx_pool_t *pool, size_t size, ajp_msg_t **rmsg);

/*
 * Create an AJP Message's buffer from pool
 *
 * @param pool      memory pool to allocate AJP message from
 * @param size      size of the buffer to create
 * @param rmsg      Pointer to newly created AJP message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_create_buffer(ngx_pool_t *pool, size_t size, ajp_msg_t *msg);

/*
 * Create an AJP Message from pool without buffer
 *
 * @param pool      memory pool to allocate AJP message from
 * @param rmsg      Pointer to newly created AJP message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_create_without_buffer(ngx_pool_t *pool, ajp_msg_t **rmsg);

/*
 * Allocate a msg to send data
 *
 * @param pool      pool to allocate from
 * @param msg       returned AJP message
 * @return          NGX_OK or error
 */
ngx_int_t  ajp_alloc_data_msg(ngx_pool_t *pool, ajp_msg_t *msg);

/*
 * Finalize a data message
 *
 * @param msg       returned AJP message
 * @param size      size of the data to send
 * @return          NGX_OK or error
 */
ngx_int_t  ajp_data_msg_end(ajp_msg_t *msg, size_t len);

/*
 * Dump up to the first DUMP_LENGTH bytes on an AJP Message
 *
 * @param pool      pool to allocate from
 * @param msg       AJP Message to dump
 * @param err       error string to display
 * @return          dump message
 */
u_char * ajp_msg_dump(ngx_pool_t *pool, ajp_msg_t *msg, char *err);


/*
 * Initialize the headers of request and reponse
 */
void ajp_header_init(void);

/*
 * Fill the request packet into AJP message
 *
 * @param msg       AJP message
 * @param r         current request
 * @param alcf      AJP configration structure
 * @return          NGX_OK or error
 */
ngx_int_t ajp_marshal_into_msgb(ajp_msg_t *msg,
        ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf);

/*
 * Parse the binary AJP response packet
 *
 * @param msg       AJP message
 * @param r         current request
 * @param alcf      AJP configration structure
 * @return          NGX_OK or error
 */
ngx_int_t ajp_unmarshal_response(ajp_msg_t *msg,
        ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf);

/*
 * Handle the CPING/CPONG messages
 * TODO: health check
 */

/*
 * Serialize in an AJP Message a PING command
 *
 * +-----------------------+
 * | PING CMD (1 byte)     |
 * +-----------------------+
 *
 * @param smsg      AJP message to put serialized message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_serialize_ping(ajp_msg_t *msg);

/*
 * Serialize in an AJP Message a CPING command
 *
 * +-----------------------+
 * | CPING CMD (1 byte)    |
 * +-----------------------+
 *
 * @param smsg      AJP message to put serialized message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_serialize_cping(ajp_msg_t *msg);


#endif /* NGX_HTTP_AJP_H */
