
/*
 * Copyright (C) Weibin Yao(yaoweibin@gmail.com)
 */

/*Main source copy from Apache's mod_ajp_proxy*/

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
#include "ajp.h"
#include "ajp_header.h"
#include "ngx_ajp_handler.h"
#include "ngx_ajp_module.h"

extern volatile ngx_cycle_t  *ngx_cycle;

typedef struct{
    ngx_str_t name;
    ngx_uint_t hash;
    ngx_uint_t code;
} request_known_headers_t;

typedef struct{
    ngx_str_t name;
    ngx_str_t lowcase_name;
    ngx_uint_t hash;
} response_known_headers_t;

static request_known_headers_t request_known_headers[] = {
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
};

static response_known_headers_t response_known_headers[] = {
    {ngx_string("Content-Type\0"), ngx_string("content-type\0"), 0},
    {ngx_string("Content-Language\0"), ngx_string("content-language\0"), 0},
    {ngx_string("Content-Length\0"), ngx_string("content-length\0"), 0}, 
    {ngx_string("Date\0"), ngx_string("date\0"), 0},
    {ngx_string("Last-Modified\0"), ngx_string("last-modified\0"), 0},
    {ngx_string("Location\0"), ngx_string("location\0"), 0},
    {ngx_string("Set-Cookie\0"), ngx_string("set-cookie\0"), 0},
    {ngx_string("Set-Cookie2\0"), ngx_string("set-cookie2\0"), 0},
    {ngx_string("Servlet-Engine\0"), ngx_string("servlet-engine\0"), 0},
    {ngx_string("Status\0"), ngx_string("status\0"), 0},
    {ngx_string("WWW-Authenticate\0"), ngx_string("www-authenticate\0"), 0},
    {ngx_null_string, ngx_null_string, 0}
};

static void response_known_headers_calc_hash (void)
{
    static ngx_int_t is_calc_response_hash = 0;
    response_known_headers_t *header;

    if (is_calc_response_hash) {
        return;
    }

    is_calc_response_hash = 1;

    header = response_known_headers;

    while (header->name.len != 0) {
        header->hash = 
            ngx_hash_key(header->lowcase_name.data, header->lowcase_name.len - 1);

        header++;
    }
}

static ngx_int_t get_res_header_for_sc(int sc, ngx_table_elt_t *h)
{
    response_known_headers_t *header;

    sc = sc & 0X00FF;

    response_known_headers_calc_hash();

    if(sc <= SC_RES_HEADERS_NUM && sc > 0) {
        header = &response_known_headers[sc - 1];

        h->key = header->name;
        h->lowcase_key = header->lowcase_name.data;
        h->hash = header->hash;
    }
    else {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t get_res_unknown_header_by_str(ngx_str_t *name,
        ngx_table_elt_t *h, ngx_pool_t *pool) 
{
    h->key = *name;

    h->lowcase_key = ngx_pnalloc(pool, h->key.len + 1);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    h->hash = ngx_hash_strlow(h->lowcase_key, h->key.data, h->key.len); 

    h->lowcase_key[h->key.len] = '\0';

    return NGX_OK;
}

#define UNKNOWN_METHOD (-1)

static ngx_uint_t sc_for_req_get_headers_num(ngx_list_part_t *part)
{
    ngx_uint_t num = 0;

    while (part) {
        num += part->nelts;
        part = part->next;
    }

    return num;
}

static void request_known_headers_calc_hash (void)
{
    static ngx_int_t is_calc_request_hash = 0;
    request_known_headers_t *header;

    if (is_calc_request_hash) {
        return;
    }

    is_calc_request_hash = 1;

    header = request_known_headers;

    while (header->name.len != 0) {
        header->hash = ngx_hash_key(header->name.data, header->name.len);

        header++;
    }
}

static ngx_uint_t request_known_headers_find_hash (ngx_uint_t hash)
{
    request_known_headers_t *header;

    header = request_known_headers;

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

    request_known_headers_calc_hash();
    
    return (int)request_known_headers_find_hash(header->hash);
}

static ngx_str_t *sc_for_req_get_header_vaule_by_hash(
        ngx_list_part_t *part, u_char *lowcase_key, size_t len)
{
    ngx_uint_t       i, hash;
    ngx_table_elt_t *header;


    hash = ngx_hash_key(lowcase_key, len);

    header = part->elts;
    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == hash) {
            return &header->value;
        }
    }

    return NULL;
}

static int sc_for_req_method_by_id(ngx_http_request_t *r)
{
    int method_id = r->method;

    if (method_id <= NGX_HTTP_UNKNOWN || method_id > NGX_HTTP_TRACE) {
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

static void sc_for_req_auth_type(ngx_http_request_t *r, ngx_str_t *auth_type)
{
    size_t     i;
    ngx_str_t *auth;

    auth_type->len = 0;

    if (r->headers_in.authorization == NULL) {
        return;
    }

    auth = &r->headers_in.authorization->value;

    for(i = 0; i < auth->len; i++) {
        if (auth->data[i] == ' ') {
            break;
        }
    }

    if (i > 0) {
        auth_type->data = auth->data;
        auth_type->len = i - 1;
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

ngx_int_t ajp_marshal_into_msgb(ajp_msg_t *msg,
        ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf)
{
    int sc;
    int method;
    uint16_t port;
    ngx_uint_t i, num_headers = 0;
    u_char is_ssl = 0;
    ngx_str_t *remote_host, *remote_addr, temp_str, *jvm_route, port_str;
    struct sockaddr_in *addr;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "Into ajp_marshal_into_msgb, uri: \"%V\"", &r->uri);

    if ((method = sc_for_req_method_by_id(r)) == UNKNOWN_METHOD) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb - No such method %s",
                r->method);
        return AJP_EBAD_METHOD;
    }

    /*is_ssl = (u_char) ap_proxy_conn_is_https(r->connection);*/

    part = &r->headers_in.headers.part;

    if (alcf->upstream.pass_request_headers) {
        num_headers = sc_for_req_get_headers_num(part);
    }

    remote_host = remote_addr = &r->connection->addr_text;

    addr = (struct sockaddr_in *) r->connection->local_sockaddr;
    /*'struct sockaddr_in' and 'struct sockaddr_in6' has the same offset of port*/
    port = ntohs(addr->sin_port);

    ajp_msg_reset(msg);

    if (ajp_msg_append_uint8(msg, CMD_AJP13_FORWARD_REQUEST)     ||
            ajp_msg_append_uint8(msg, method)                        ||
            ajp_msg_append_string(msg, &r->http_protocol)            ||
            ajp_msg_append_string(msg, &r->uri)                      ||
            ajp_msg_append_string(msg, remote_addr)                  ||
            ajp_msg_append_string(msg, remote_host)                  ||
            ajp_msg_append_string(msg, &r->headers_in.server)        ||
            ajp_msg_append_uint16(msg, port)                         ||
            ajp_msg_append_uint8(msg, is_ssl)                        ||
            ajp_msg_append_uint16(msg, (uint16_t) num_headers)) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb: "
                "Error appending the message begining");
        return AJP_EOVERFLOW;
    }

    header = part->elts;
    if (alcf->upstream.pass_request_headers) {
        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if ((sc = sc_for_req_header(&header[i])) != UNKNOWN_METHOD) {
                if (ajp_msg_append_uint16(msg, (uint16_t)sc)) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                            "ajp_marshal_into_msgb: "
                            "Error appending the header name");
                    return AJP_EOVERFLOW;
                }
            }
            else {
                if (ajp_msg_append_string(msg, &header[i].key)) {
                    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                            "ajp_marshal_into_msgb: "
                            "Error appending the header name");
                    return AJP_EOVERFLOW;
                }
            }

            if (ajp_msg_append_string(msg, &header[i].value)) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_marshal_into_msgb: "
                        "Error appending the header value");
                return AJP_EOVERFLOW;
            }
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: Header[%d] [%V] = [%V], size:%z",
                    i, &header[i].key, &header[i].value, ngx_buf_size(msg->buf));
        }
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

    if (r->headers_in.user.len != 0) {
        if (ajp_msg_append_uint8(msg, SC_A_REMOTE_USER) ||
                ajp_msg_append_string(msg, &r->headers_in.user)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the remote user");
            return AJP_EOVERFLOW;
        }

    }

    sc_for_req_auth_type(r, &temp_str);
    if (temp_str.len > 0) {
        if (ajp_msg_append_uint8(msg, SC_A_AUTH_TYPE) ||
                ajp_msg_append_string(msg, &temp_str)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the auth type");
            return AJP_EOVERFLOW;
        }
    }

    /* XXXX  ebcdic (args converted?) */
    if (r->args.len > 0) {
        if (ajp_msg_append_uint8(msg, SC_A_QUERY_STRING) ||
                ajp_msg_append_string(msg, &r->args)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending the query string");
            return AJP_EOVERFLOW;
        }
    }

    jvm_route = sc_for_req_get_header_vaule_by_hash(&r->headers_in.headers.part,
            (u_char *)"session-route", sizeof("session-route") - 1);
    if (jvm_route != NULL) {
        if (ajp_msg_append_uint8(msg, SC_A_JVM_ROUTE) ||
                ajp_msg_append_string(msg, jvm_route)) {
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
    /*TODO SSL*/
    /*
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
     */

    /* Forward the remote port information, which was forgotten
     * from the builtin data of the AJP 13 protocol.
     * Since the servlet spec allows to retrieve it via getRemotePort(),
     * we provide the port to the Tomcat connector as a request
     * attribute. Modern Tomcat versions know how to retrieve
     * the remote port from this attribute.
     */
    {
        u_char buf[6] = {0};
        temp_str.data = (u_char *)SC_A_REQ_REMOTE_PORT;
        temp_str.len = sizeof(SC_A_REQ_REMOTE_PORT) - 1;

        addr = (struct sockaddr_in *) r->connection->sockaddr;
        /*'struct sockaddr_in' and 'struct sockaddr_in6' has the same offset of port*/
        port = ntohs(addr->sin_port);
        /*port < 65536*/
        ngx_snprintf(buf, 6, "%d", port);
        port_str.data = buf;
        port_str.len = ngx_strlen(buf);

        if (ajp_msg_append_uint8(msg, SC_A_REQ_ATTRIBUTE) ||
                ajp_msg_append_string(msg, &temp_str)   ||
                ajp_msg_append_string(msg, &port_str)) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_marshal_into_msgb: "
                    "Error appending attribute %V=%V",
                    &temp_str, &port_str);
            return AJP_EOVERFLOW;
        }

        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb: attribute %V %V", &temp_str, &port_str);
    }
    /* Use the environment vars prefixed with AJP_
     * and pass it to the header striping that prefix.
     */
    /* TODO
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
    */

    if (ajp_msg_append_uint8(msg, SC_A_ARE_DONE)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_marshal_into_msgb: "
                "Error appending the message end");
        return AJP_EOVERFLOW;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "ajp_marshal_into_msgb: Done, buff_size:%z", ngx_buf_size(msg->buf));

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

static ngx_int_t ajp_unmarshal_response(ajp_msg_t *msg,
        ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf)
{
    uint16_t status;
    ngx_int_t rc;
    ngx_str_t str;
    uint16_t name;
    uint16_t  num_headers;
    int i;
    u_char line[1024], *last;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_t            *u;
    ngx_http_ajp_ctx_t             *a;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);

    u = r->upstream;

    rc = ajp_msg_get_uint16(msg, &status);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_unmarshal_response: Null status");
        return rc;
    }
    u->headers_in.status_n = status;

    rc = ajp_msg_get_string(msg, &str);

    if (rc == NGX_OK) {
        last = ngx_snprintf(line, 1024, "%d %V", status, &str);

        str.data = line;
        str.len = last - line;

        u->headers_in.status_line.data = ngx_pstrdup(r->pool, &str);
        u->headers_in.status_line.len = str.len;
    } else {
        u->headers_in.status_line.data = NULL;
        u->headers_in.status_line.len = 0;
    }

    if (u->state) {
        u->state->status = u->headers_in.status_n;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "ajp_unmarshal_response: status = %d", status);

    rc = ajp_msg_get_uint16(msg, &num_headers);

    if (rc != NGX_OK) {
        num_headers = 0;
    }

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "ajp_unmarshal_response: Number of headers is = %d",
            num_headers);

    for(i = 0 ; i < (int) num_headers ; i++) {

        rc  = ajp_msg_peek_uint16(msg, &name);
        if (rc != NGX_OK) {
            return rc;
        }

        /* a header line has been parsed successfully */

        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        if ((name & 0XFF00) == 0XA000) {
            ajp_msg_get_uint16(msg, &name);

            rc = get_res_header_for_sc(name, h);

            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_unmarshal_response: "
                        "No such sc (%08Xd)",
                        name);
                return AJP_EBAD_HEADER;
            }

        } else {
            name = 0;
            rc = ajp_msg_get_string(msg, &str);

            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                        "ajp_unmarshal_response: "
                        "Null header name");
                return rc;
            }

            rc = get_res_unknown_header_by_str(&str, h, r->pool);
            if (rc != NGX_OK) {
                return rc;
            }
        }

        rc = ajp_msg_get_string(msg, &h->value);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                    "ajp_unmarshal_response: "
                    "Null header value");
            return rc;
        }

        hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                h->lowcase_key, h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_ERROR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http ajp header: \"%V: %V\"",
                &h->key, &h->value);

    }

    return NGX_OK;
}

/* parse the header */
ngx_int_t ajp_parse_header(ngx_http_request_t  *r, ngx_http_ajp_loc_conf_t *alcf, ajp_msg_t *msg)
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
                "ajp_parse_headers: wrong type %02Xd expecting 0x04", result);
        return AJP_EBAD_HEADER;
    }

    return ajp_unmarshal_response(msg, r, alcf);
}

/* parse the body and return data address and length */
ngx_int_t  ajp_parse_data(ngx_http_request_t  *r, ajp_msg_t *msg,
        uint16_t *len)
{
    u_char result;
    ngx_int_t rc;

    rc = ajp_msg_get_uint8(msg, &result);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_data: ajp_msg_get_byte failed");
        return rc;
    }

    if (result != CMD_AJP13_SEND_BODY_CHUNK) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_parse_data: wrong type %02Xd expecting 0x03", result);
        return AJP_EBAD_HEADER;
    }

    rc = ajp_msg_get_uint16(msg, len);
    if (rc != NGX_OK) {
        return rc;
    }


    return NGX_OK;
}

/* parse the msg to read the type */
int ajp_parse_type(ngx_http_request_t  *r, ajp_msg_t *msg)
{
    u_char result;

    ajp_msg_peek_uint8(msg, &result);

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
            "ajp_parse_type: got 0x%02Xd", result);

    return (int) result;
}

/*
 * Allocate a msg to send data
 */
ngx_int_t  ajp_alloc_data_msg(ngx_pool_t *pool, ajp_msg_t **msg)
{
    ngx_int_t rc;

    if ((rc = ajp_msg_create(pool, AJP_HEADER_SZ + 1, msg)) != NGX_OK) {
        return rc;
    }

    ajp_msg_reset(*msg);

    return NGX_OK;
}

ngx_chain_t *ajp_data_msg_send_body(ngx_http_request_t *r, size_t max_size,
        ngx_chain_t **body)
{
    size_t size;
    ngx_buf_t *b_in, *b_out;
    ngx_chain_t *out, *cl, *in;
    ajp_msg_t *msg;

    if (*body == NULL) {
        return NULL;
    }

    if (ajp_alloc_data_msg(r->pool, &msg) != NGX_OK) {
        return NULL;
    }

    out = cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = msg->buf;

    max_size -= AJP_HEADER_SZ;
    size = 0;
    in = *body;

    b_out = NULL;
    while (in) {
        b_in = in->buf;

        b_out = ngx_alloc_buf(r->pool);
        if (b_out == NULL) {
            return NULL;
        }
        ngx_memcpy(b_out, b_in, sizeof(ngx_buf_t));

        if (b_in->in_file) {
            if ((size_t)(b_in->file_last - b_in->file_pos) <= (max_size - size)){

                b_out->file_pos = b_in->file_pos;
                b_out->file_last = b_in->file_pos = b_in->file_last;

                size += b_out->file_last - b_out->file_pos;
            }
            else if ((size_t)(b_in->file_last - b_in->file_pos) > (max_size - size))
            {
                b_out->file_pos = b_in->file_pos;
                b_in->file_pos += max_size - size;
                b_out->file_last = b_in->file_pos;

                size += b_out->file_last - b_out->file_pos;
            }
        }
        else {
            if ((size_t)(b_in->last - b_in->pos) <= (max_size - size)){

                b_out->pos = b_in->pos;
                b_out->last = b_in->pos = b_in->last;

                size += b_out->last - b_out->pos;
            }
            else if ((size_t)(b_in->last - b_in->pos) > (max_size - size))
            {
                b_out->pos = b_in->pos;
                b_in->pos += max_size - size;
                b_out->last = b_in->pos;

                size += b_out->last - b_out->pos;
            }
        }

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NULL;
        }

        cl = cl->next;
        cl->buf = b_out;

        if (size >= max_size) {
            break;
        }
        else {
            in = in->next;
        }
    }

    if (b_out != NULL && b_out->last) {
        /*the last buffer ?*/
    }

    *body = in;
    cl->next = NULL;
    
    ajp_data_msg_end(msg, size);

    return out;
}

ngx_int_t  ajp_data_msg_end(ajp_msg_t *msg, size_t len)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    buf->pos = buf->start;
    buf->last = buf->start + AJP_HEADER_SZ;

    ajp_msg_end(msg);

    buf->start[AJP_HEADER_SZ - 2] = (u_char)((len >> 8) & 0xFF);
    buf->start[AJP_HEADER_SZ - 1] = (u_char)(len & 0xFF);

    /*len include AJP_HEADER_SIZE_LEN*/
    len += AJP_HEADER_SZ_LEN;
    buf->start[AJP_HEADER_LEN - 2] = (u_char)((len >> 8) & 0xFF);
    buf->start[AJP_HEADER_LEN - 1] = (u_char)(len & 0xFF);

    return NGX_OK;
}
