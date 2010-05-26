/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ajp_header.h"
#include "ajp.h"

extern volatile ngx_cycle_t  *ngx_cycle;

typedef {
    ngx_str_t name;
    ngx_uint_t hash;
    ngx_uint_t code;
} request_known_headers_t;

static request_known_headers_t know_headers[] = {
    {ngx_string("accept"), 0, SC_REQ_ACCEPT},
    {ngx_string("accept-charset"), 0, SC_REQ_ACCEPT_CHARSET},
    {ngx_string("accept-encoding"), 0, SC_REQ_ACCEPT_ENCODING},
    {ngx_string("accept-language"), 0, SC_REQ_ACCEPT_LANGUAGE},
    {ngx_string("authorization"), 0, SC_REQ_AUTHORIZATION},
    {ngx_string("connection"), 0, SC_REQ_CONNECTION},
    {ngx_string("content-type"), 0, SC_REQ_CONTENT_TYPE},
    {ngx_string("content-length"), 0, SC_REQ_CONTENT_LENGTH},
    {ngx_string("cookie"), 0, SC_REQ_COOKIE},
    {ngx_string("cookie2"), 0, SC_REQ_COOKIE2},
    {ngx_string("host"), 0, SC_REQ_HOST},
    {ngx_string("pragma"), 0, SC_REQ_PRAGMA},
    {ngx_string("referer"), 0,  SC_REQ_REFERER},
    {ngx_string("user-agent"), 0, SC_REQ_USER_AGENT},
    {ngx_null_string, 0, 0}
}

static const char *response_trans_headers[] = {
    "Content-Type",
    "Content-Language",
    "Content-Length",
    "Date",
    "Last-Modified",
    "Location",
    "Set-Cookie",
    "Set-Cookie2",
    "Servlet-Engine",
    "Status",
    "WWW-Authenticate"
};

static const char *long_res_header_for_sc(int sc)
{
    const char *rc = NULL;
    sc = sc & 0X00FF;
    if(sc <= SC_RES_HEADERS_NUM && sc > 0) {
        rc = response_trans_headers[sc - 1];
    }

    return rc;
}

#define UNKNOWN_METHOD (-1)

static ngx_int_t is_calc_hash = 0;

static void request_know_headers_calc_hash (void)
{
    request_known_headers_t *header;

    if (is_calc_hash) {
        return;
    }

    is_calc_hash = 1;

    header = known_headers;

    while (header->name.len != 0) {
        header->hash = ngx_hash_key(header->name.data, header->name.len);

        header++;
    }
}

static ngx_uint_t request_know_headers_find_hash (ngx_uint_t hash)
{
    request_known_headers_t *header;

    header = known_headers;

    while (header->name.len != 0) {
        if (header->hash == hash) {
            return header->code;
        }

        header++;
    }

    return UNKNOWN_METHOD;
}

static int sc_for_req_header(ngx_table_elt_t *header)
{
    size_t len = header->key.len;

    /* ACCEPT-LANGUAGE is the longest header
     * that is of interest.
     */
    if (len < 4 || len > 15) {
        return UNKNOWN_METHOD;
    }

    request_know_headers_calc_hash();
    
    return (int)request_known_headers_find_hash(header->hash);
}

static int sc_for_req_method_by_id(ngx_http_request_t *r)
{
    int method_id = r->method;

    if (method_id <= NGX_HTTP_UNKOWN || method_id > NGX_HTTP_TRACE) {
        return UNKNOWN_METHOD;
    }

    switch (method_id) {
        case NGX_HTTP_GET:
            return SC_M_GET;
        case NGX_HTTP_HEAD:
            return SC_M_HEAD;
        case NGX_HTTP_POST:
            return SC_M_POST;
        case NGX_HTTP_PUT:
            return SC_M_PUT;
        case NGX_HTTP_DELETE:
            return SC_M_DELETE;
        case NGX_HTTP_MKCOL:
            return SC_M_MKCOL;
        case NGX_HTTP_COPY:
            return SC_M_COPY;
        case NGX_HTTP_MOVE:
            return SC_M_MOVE;
        case NGX_HTTP_OPTIONS:
            return SC_M_OPTIONS;
        case NGX_HTTP_PROPFIND:
            return SC_M_PROPFIND;
        case NGX_HTTP_PROPPATCH:
            return SC_M_PROPPATCH;
        case NGX_HTTP_LOCK:
            return SC_M_LOCK;
        case NGX_HTTP_UNLOCK:
            return SC_M_UNLOCK;
        case NGX_HTTP_TRACE:
            return SC_M_TRACE;
        default:
            return UNKNOWN_METHOD;
    }
}

/*
 * Message structure
 *
 *
 AJPV13_REQUEST/AJPV14_REQUEST=
 request_prefix (1) (byte)
 method         (byte)
 protocol       (string)
 req_uri        (string)
 remote_addr    (string)
 remote_host    (string)
 server_name    (string)
 server_port    (short)
 is_ssl         (boolean)
 num_headers    (short)
 num_headers*(req_header_name header_value)

 ?context       (byte)(string)
 ?servlet_path  (byte)(string)
 ?remote_user   (byte)(string)
 ?auth_type     (byte)(string)
 ?query_string  (byte)(string)
 ?jvm_route     (byte)(string)
 ?ssl_cert      (byte)(string)
 ?ssl_cipher    (byte)(string)
 ?ssl_session   (byte)(string)
 ?ssl_key_size  (byte)(int)      via JkOptions +ForwardKeySize
 request_terminator (byte)
 ?body          content_length*(var binary)

 */

static ngx_int_t ajp_marshal_into_msgb(ajp_msg_t *msg,
        ngx_http_request_t *r,
        apr_uri_t *uri)
{
    int method;
    uint16_t port;
    uint32_t i, num_headers = 0;
    u_char is_ssl = 0;
    ngx_str_t *remote_host, *remote_addr;
    struct sockaddr_in *addr;
    const char *session_route, *envvar;
    const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
    const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "Into ajp_marshal_into_msgb");

    if ((method = sc_for_req_method_by_id(r)) == UNKNOWN_METHOD) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb - No such method %s",
                r->method);
        return AJP_EBAD_METHOD;
    }

    /*is_ssl = (u_char) ap_proxy_conn_is_https(r->connection);*/

    if (r->headers_in) {
        const ngx_list_part_t *p = &r->headers_in.headers.part;
        num_headers = p->nelts;
    }

    remote_host = remote_addr = &r->connection->addr_text;

    addr = (struct sockaddr_in *) r->connection->local_sockaddr;
    /*'struct sockaddr_in' and 'struct sockaddr_in6' has the same offset of port*/
    port = addr->sin_port;

    ajp_msg_reset(msg);

    if (ajp_msg_append_uint8(msg, CMD_AJP13_FORWARD_REQUEST)     ||
            ajp_msg_append_uint8(msg, method)                        ||
            ajp_msg_append_string(msg, &r->http_protocol)            ||
            ajp_msg_append_string(msg, &r->unparsed_uri)             ||
            ajp_msg_append_string(msg, remote_addr)                  ||
            ajp_msg_append_string(msg, remote_host)                  ||
            ajp_msg_append_string(msg, &r->headers_in.server)        ||
            ajp_msg_append_uint16(msg, port)                         ||
            ajp_msg_append_uint8(msg, is_ssl)                        ||
            ajp_msg_append_uint16(msg, (uint16_t) num_headers)) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb: "
                "Error appending the message begining");
        return APR_EGENERAL;
    }

    for (i = 0 ; i < num_headers ; i++) {
        int sc;
        const ngx_list_part_t *p = &r->headers_in.headers.part;
        const ngx_table_elt_t *elts = p->elts;

        if ((sc = sc_for_req_header(&elts[i])) != UNKNOWN_METHOD) {
            if (ajp_msg_append_uint16(msg, (uint16_t)sc)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending the header name");
                return AJP_EOVERFLOW;
            }
        }
        else {
            if (ajp_msg_append_string(msg, &elts[i].key)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending the header name");
                return AJP_EOVERFLOW;
            }
        }

        if (ajp_msg_append_string(msg, &elts[i].value)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the header value");
            return AJP_EOVERFLOW;
        }
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb: Header[%d] [%V] = [%V]",
                i, &elts[i].key, &elts[i].value);
    }

    /* XXXX need to figure out how to do this
       if (s->secret) {
       if (ajp_msg_append_uint8(msg, SC_A_SECRET) ||
       ajp_msg_append_string(msg, s->secret)) {
       ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
       "Error ajp_marshal_into_msgb - "
       "Error appending secret");
       return APR_EGENERAL;
       }
       }
     */

    if (r->user) {
        if (ajp_msg_append_uint8(msg, SC_A_REMOTE_USER) ||
                ajp_msg_append_string(msg, r->user)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the remote user");
            return AJP_EOVERFLOW;
        }
    }
    if (r->ap_auth_type) {
        if (ajp_msg_append_uint8(msg, SC_A_AUTH_TYPE) ||
                ajp_msg_append_string(msg, r->ap_auth_type)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the auth type");
            return AJP_EOVERFLOW;
        }
    }
    /* XXXX  ebcdic (args converted?) */
    if (uri->query) {
        if (ajp_msg_append_uint8(msg, SC_A_QUERY_STRING) ||
                ajp_msg_append_string(msg, uri->query)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the query string");
            return AJP_EOVERFLOW;
        }
    }
    if ((session_route = apr_table_get(r->notes, "session-route"))) {
        if (ajp_msg_append_uint8(msg, SC_A_JVM_ROUTE) ||
                ajp_msg_append_string(msg, session_route)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the jvm route");
            return AJP_EOVERFLOW;
        }
    }
    /* XXX: Is the subprocess_env a right place?
     * <Location /examples>
     *   ProxyPass ajp://remote:8009/servlets-examples
     *   SetEnv SSL_SESSION_ID CUSTOM_SSL_SESSION_ID
     * </Location>
     */
    /*
     * Only lookup SSL variables if we are currently running HTTPS.
     * Furthermore ensure that only variables get set in the AJP message
     * that are not NULL and not empty.
     */
    if (is_ssl) {
        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                        AJP13_SSL_CLIENT_CERT_INDICATOR))
                && envvar[0]) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_CERT)
                    || ajp_msg_append_string(msg, envvar)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending the SSL certificates");
                return AJP_EOVERFLOW;
            }
        }

        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                        AJP13_SSL_CIPHER_INDICATOR))
                && envvar[0]) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_CIPHER)
                    || ajp_msg_append_string(msg, envvar)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending the SSL ciphers");
                return AJP_EOVERFLOW;
            }
        }

        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                        AJP13_SSL_SESSION_INDICATOR))
                && envvar[0]) {
            if (ajp_msg_append_uint8(msg, SC_A_SSL_SESSION)
                    || ajp_msg_append_string(msg, envvar)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending the SSL session");
                return AJP_EOVERFLOW;
            }
        }

        /* ssl_key_size is required by Servlet 2.3 API */
        if ((envvar = ap_proxy_ssl_val(r->pool, r->server, r->connection, r,
                        AJP13_SSL_KEY_SIZE_INDICATOR))
                && envvar[0]) {

            if (ajp_msg_append_uint8(msg, SC_A_SSL_KEY_SIZE)
                    || ajp_msg_append_uint16(msg, (unsigned short) atoi(envvar))) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "Error ajp_marshal_into_msgb - "
                        "Error appending the SSL key size");
                return APR_EGENERAL;
            }
        }
    }
    /* Forward the remote port information, which was forgotten
     * from the builtin data of the AJP 13 protocol.
     * Since the servlet spec allows to retrieve it via getRemotePort(),
     * we provide the port to the Tomcat connector as a request
     * attribute. Modern Tomcat versions know how to retrieve
     * the remote port from this attribute.
     */
    {
        const char *key = SC_A_REQ_REMOTE_PORT;
        char *val = apr_itoa(r->pool, r->connection->remote_addr->port);
        if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
                ajp_msg_append_string(msg, key)   ||
                ajp_msg_append_string(msg, val)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending attribute %s=%s",
                    key, val);
            return AJP_EOVERFLOW;
        }
    }
    /* Use the environment vars prefixed with AJP_
     * and pass it to the header striping that prefix.
     */
    for (i = 0; i < (uint32_t)arr->nelts; i++) {
        if (!strncmp(elts[i].key, "AJP_", 4)) {
            if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
                    ajp_msg_append_string(msg, elts[i].key + 4)   ||
                    ajp_msg_append_string(msg, elts[i].val)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending attribute %s=%s",
                        elts[i].key, elts[i].val);
                return AJP_EOVERFLOW;
            }
        }
    }

    if (ajp_msg_append_uint8(msg, SC_A_ARE_DONE)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb: "
                "Error appending the message end");
        return AJP_EOVERFLOW;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "ajp_marshal_into_msgb: Done");
    return NGX_OK;
}

/*
   AJPV13_RESPONSE/AJPV14_RESPONSE:=
   response_prefix (2)
   status          (short)
   status_msg      (short)
   num_headers     (short)
   num_headers*(res_header_name header_value)
 *body_chunk
 terminator      boolean <! -- recycle connection or not  -->

req_header_name :=
sc_req_header_name | (string)

res_header_name :=
sc_res_header_name | (string)

header_value :=
(string)

body_chunk :=
length  (short)
body    length*(var binary)

 */

static int addit_dammit(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

static ngx_int_t ajp_unmarshal_response(ajp_msg_t *msg,
        ngx_http_request_t *r,
        proxy_dir_conf *dconf)
{
    uint16_t status;
    ngx_int_t rc;
    const char *ptr;
    uint16_t  num_headers;
    int i;

    rc = ajp_msg_get_uint16(msg, &status);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_unmarshal_response: Null status");
        return rc;
    }
    r->status = status;

    rc = ajp_msg_get_string(msg, &ptr);
    if (rc == NGX_OK) {
#if defined(AS400) || defined(_OSD_POSIX) /* EBCDIC platforms */
        ptr = apr_pstrdup(r->pool, ptr);
        ap_xlate_proto_from_ascii(ptr, strlen(ptr));
#endif
        r->status_line =  apr_psprintf(r->pool, "%d %s", status, ptr);
    } else {
        r->status_line = NULL;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "ajp_unmarshal_response: status = %d", status);

    rc = ajp_msg_get_uint16(msg, &num_headers);
    if (rc == NGX_OK) {
        apr_table_t *save_table;

        /* First, tuck away all already existing cookies */
        /*
         * Could optimize here, but just in case we want to
         * also save other headers, keep this logic.
         */
        save_table = apr_table_make(r->pool, num_headers + 2);
        apr_table_do(addit_dammit, save_table, r->headers_out,
                "Set-Cookie", NULL);
        r->headers_out = save_table;
    } else {
        r->headers_out = NULL;
        num_headers = 0;
    }

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "ajp_unmarshal_response: Number of headers is = %d",
            num_headers);

    for(i = 0 ; i < (int) num_headers ; i++) {
        uint16_t name;
        const char *stringname;
        const char *value;
        rc  = ajp_msg_peek_uint16(msg, &name);
        if (rc != NGX_OK) {
            return rc;
        }

        if ((name & 0XFF00) == 0XA000) {
            ajp_msg_get_uint16(msg, &name);
            stringname = long_res_header_for_sc(name);
            if (stringname == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_unmarshal_response: "
                        "No such sc (%08x)",
                        name);
                return AJP_EBAD_HEADER;
            }
        } else {
            name = 0;
            rc = ajp_msg_get_string(msg, &stringname);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_unmarshal_response: "
                        "Null header name");
                return rc;
            }
#if defined(AS400) || defined(_OSD_POSIX)
            ap_xlate_proto_from_ascii(stringname, strlen(stringname));
#endif
        }

        rc = ajp_msg_get_string(msg, &value);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_unmarshal_response: "
                    "Null header value");
            return rc;
        }

        /* Set-Cookie need additional processing */
        if (!strcasecmp(stringname, "Set-Cookie")) {
            value = ap_proxy_cookie_reverse_map(r, dconf, value);
        }
        /* Location, Content-Location, URI and Destination need additional
         * processing */
        else if (!strcasecmp(stringname, "Location")
                || !strcasecmp(stringname, "Content-Location")
                || !strcasecmp(stringname, "URI")
                || !strcasecmp(stringname, "Destination"))
        {
            value = ap_proxy_location_reverse_map(r, dconf, value);
        }

#if defined(AS400) || defined(_OSD_POSIX)
        ap_xlate_proto_from_ascii(value, strlen(value));
#endif
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_unmarshal_response: Header[%d] [%s] = [%s]",
                i, stringname, value);

        apr_table_add(r->headers_out, stringname, value);

        /* Content-type needs an additional handling */
        if (strcasecmp(stringname, "Content-Type") == 0) {
            /* add corresponding filter */
            ap_set_content_type(r, apr_pstrdup(r->pool, value));
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_unmarshal_response: ap_set_content_type done");
        }
    }

    return NGX_OK;
}

/*
 * Build the ajp header message and send it
 */
ngx_int_t ajp_send_header(apr_socket_t *sock,
        ngx_http_request_t *r,
        apr_size_t buffsize,
        apr_uri_t *uri)
{
    ajp_msg_t *msg;
    ngx_int_t rc;

    rc = ajp_msg_create(r->pool, buffsize, &msg);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_send_header: ajp_msg_create failed");
        return rc;
    }

    rc = ajp_marshal_into_msgb(msg, r, uri);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_send_header: ajp_marshal_into_msgb failed");
        return rc;
    }

    rc = ajp_ilink_send(sock, msg);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_read_header: ajp_msg_reuse failed");
        return rc;
    }
}
else {
    rc = ajp_msg_create(r->pool, buffsize, msg);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_read_header: ajp_msg_create failed");
        return rc;
    }
}
ajp_msg_reset(*msg);
rc = ajp_ilink_receive(sock, *msg);
if (rc != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "ajp_read_header: ajp_ilink_receive failed");
    return rc;
}
rc = ajp_msg_peek_uint8(*msg, &result);
ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
        "ajp_read_header: ajp_ilink_received %02x", result);
return NGX_OK;
}

/* parse the msg to read the type */
int ajp_parse_type(ngx_http_request_t  *r, ajp_msg_t *msg)
{
    u_char result;
    ajp_msg_peek_uint8(msg, &result);
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "ajp_parse_type: got %02x", result);
    return (int) result;
}

/* parse the header */
ngx_int_t ajp_parse_header(ngx_http_request_t  *r, proxy_dir_conf *conf,
        ajp_msg_t *msg)
{
    u_char result;
    ngx_int_t rc;

    rc = ajp_msg_get_uint8(msg, &result);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_headers: ajp_msg_get_byte failed");
        return rc;
    }
    if (result != CMD_AJP13_SEND_HEADERS) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_headers: wrong type %02x expecting 0x04", result);
        return AJP_EBAD_HEADER;
    }
    return ajp_unmarshal_response(msg, r, conf);
}

/* parse the body and return data address and length */
ngx_int_t  ajp_parse_data(ngx_http_request_t  *r, ajp_msg_t *msg,
        uint16_t *len, char **ptr)
{
    u_char result;
    ngx_int_t rc;
    uint16_t expected_len;

    rc = ajp_msg_get_uint8(msg, &result);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_data: ajp_msg_get_byte failed");
        return rc;
    }
    if (result != CMD_AJP13_SEND_BODY_CHUNK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_data: wrong type %02x expecting 0x03", result);
        return AJP_EBAD_HEADER;
    }
    rc = ajp_msg_get_uint16(msg, len);
    if (rc != NGX_OK) {
        return rc;
    }
    /*
     * msg->len contains the complete length of the message including all
     * headers. So the expected length for a CMD_AJP13_SEND_BODY_CHUNK is
     * msg->len minus the sum of
     * AJP_HEADER_LEN    : The length of the header to every AJP message.
     * AJP_HEADER_SZ_LEN : The header giving the size of the chunk.
     * 1                 : The CMD_AJP13_SEND_BODY_CHUNK indicator byte (0x03).
     * 1                 : The last byte of this message always seems to be
     *                     0x00 and is not part of the chunk.
     */
    expected_len = msg->len - (AJP_HEADER_LEN + AJP_HEADER_SZ_LEN + 1 + 1);
    if (*len != expected_len) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_data: Wrong chunk length. Length of chunk is %i,"
                " expected length is %i.", *len, expected_len);
        return AJP_EBAD_HEADER;
    }
    *ptr = (char *)&(msg->buf[msg->pos]);
    return NGX_OK;
}

/*
 * Allocate a msg to send data
 */
ngx_int_t  ajp_alloc_data_msg(ngx_pool_t *pool, char **ptr, apr_size_t *len,
        ajp_msg_t **msg)
{
    ngx_int_t rc;

    if ((rc = ajp_msg_create(pool, *len, msg)) != NGX_OK)
        return rc;
    ajp_msg_reset(*msg);
    *ptr = (char *)&((*msg)->buf[6]);
    *len =  *len - 6;

    return NGX_OK;
}

/*
 * Send the data message
 */
ngx_int_t  ajp_send_data_msg(apr_socket_t *sock,
        ajp_msg_t *msg, apr_size_t len)
{

    msg->buf[4] = (u_char)((len >> 8) & 0xFF);
    msg->buf[5] = (u_char)(len & 0xFF);

    msg->len += len + 2; /* + 1 XXXX where is '\0' */

    return ajp_ilink_send(sock, msg);

}
