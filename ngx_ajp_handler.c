
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ajp.h>
#include <ajp_header.h>
#include <ngx_ajp_handler.h>

static ngx_int_t ngx_http_ajp_eval(ngx_http_request_t *r,
    ngx_http_ajp_loc_conf_t *alcf);
#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_ajp_create_key(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_http_ajp_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ajp_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ajp_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_ajp_input_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static void ngx_http_ajp_abort_request(ngx_http_request_t *r);
static void ngx_http_ajp_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

ngx_int_t
ngx_http_ajp_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_upstream_t          *u;
    ngx_http_ajp_ctx_t       *a;
    ngx_http_ajp_loc_conf_t  *alcf;

    if (r->subrequest_in_memory) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "ngx_ajp_module does not support "
                "subrequest in memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    a = ngx_pcalloc(r->pool, sizeof(ngx_http_ajp_ctx_t));
    if (a == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, a, ngx_http_ajp_module);

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (alcf->ajp_lengths) {
        if (ngx_http_ajp_eval(r, alcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    u->schema.len = sizeof("ajp://") - 1;
    u->schema.data = (u_char *) "ajp://";

    u->output.tag = (ngx_buf_tag_t) &ngx_http_ajp_module;

    u->conf = &alcf->upstream;

#if (NGX_HTTP_CACHE)
    u->create_key = ngx_http_ajp_create_key;
#endif
    u->create_request = ngx_http_ajp_create_request;
    u->reinit_request = ngx_http_ajp_reinit_request;
    u->process_header = ngx_http_ajp_process_header;
    u->abort_request = ngx_http_ajp_abort_request;
    u->finalize_request = ngx_http_ajp_finalize_request;

    u->buffering = 1;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_ajp_input_filter;
    u->pipe->input_ctx = r;

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static ngx_int_t
ngx_http_ajp_eval(ngx_http_request_t *r, ngx_http_ajp_loc_conf_t *alcf)
{
    ngx_url_t  u;

    ngx_memzero(&u, sizeof(ngx_url_t));

    if (ngx_http_script_run(r, &u.url, alcf->ajp_lengths->elts, 0,
                            alcf->ajp_values->elts)
        == NULL)
    {
        return NGX_ERROR;
    }

    u.no_resolve = 1;

    if (ngx_parse_url(r->pool, &u) != NGX_OK) {
         if (u.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_ERROR;
    }

    if (u.no_port) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no port in upstream \"%V\"", &u.url);
        return NGX_ERROR;
    }

    r->upstream->resolved = ngx_pcalloc(r->pool,
                                        sizeof(ngx_http_upstream_resolved_t));
    if (r->upstream->resolved == NULL) {
        return NGX_ERROR;
    }

    if (u.addrs && u.addrs[0].sockaddr) {
        r->upstream->resolved->sockaddr = u.addrs[0].sockaddr;
        r->upstream->resolved->socklen = u.addrs[0].socklen;
        r->upstream->resolved->naddrs = 1;
        r->upstream->resolved->host = u.addrs[0].name;

    } else {
        r->upstream->resolved->host = u.host;
        r->upstream->resolved->port = u.port;
    }

    return NGX_OK;
}


#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_ajp_create_key(ngx_http_request_t *r)
{
    ngx_str_t                    *key;
    ngx_http_ajp_loc_conf_t  *alcf;

    key = ngx_array_push(&r->cache->keys);
    if (key == NULL) {
        return NGX_ERROR;
    }

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (ngx_http_complex_value(r, &alcf->cache_key, key) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif

static ngx_int_t
ngx_http_ajp_create_request(ngx_http_request_t *r)
{
    /*off_t                         file_pos;*/
    /*u_char                        ch, *pos;*/
    /*size_t                        size, len, key_len, val_len, padding;*/
    ajp_msg_t                    *msg;
    /*ngx_uint_t                    i, n, next;*/
    /*ngx_buf_t                    *b;*/
    ngx_chain_t                  *cl;
    /*ngx_http_script_code_pt       code;*/
    /*ngx_http_script_engine_t      e, le;*/
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t  *alcf;
    /*ngx_http_script_len_code_pt   lcode;*/

    /*len = 0;*/

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a == NULL || alcf == NULL) {
        return NGX_ERROR;
    }
    /*
    if (alcf->params_len) {
        ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

        ngx_http_script_flush_no_cacheable_variables(r, alcf->flushes);
        le.flushed = 1;

        le.ip = alcf->params_len->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            len += 1 + key_len + ((val_len > 127) ? 4 : 1) + val_len;
        }
    }
    */

    if (NGX_OK != ajp_msg_create(r->pool, alcf->ajp_header_packet_buffer_size_conf, &msg)) {
        return NGX_ERROR;
    }


    if (NGX_OK != ajp_marshal_into_msgb(msg, r, alcf)) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = msg->buf;

    /*
    if (alcf->params_len) {
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

        e.ip = alcf->params->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = alcf->params_len->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(ngx_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            *e.pos++ = (u_char) key_len;

            if (val_len > 127) {
                *e.pos++ = (u_char) (((val_len >> 24) & 0x7f) | 0x80);
                *e.pos++ = (u_char) ((val_len >> 16) & 0xff);
                *e.pos++ = (u_char) ((val_len >> 8) & 0xff);
                *e.pos++ = (u_char) (val_len & 0xff);

            } else {
                *e.pos++ = (u_char) val_len;
            }

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "ajp param: \"%*s: %*s\"",
                           key_len, e.pos - (key_len + val_len),
                           val_len, e.pos - val_len);
        }

        b->last = e.pos;
    }
    */

    if (alcf->upstream.pass_request_body) {
        a->body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

        cl->next = ajp_data_msg_send_body(r, 
                alcf->max_ajp_data_packet_size_conf ,&a->body);
    } else {
        r->upstream->request_bufs = cl;
        cl->next = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ajp_reinit_request(ngx_http_request_t *r)
{

    /*some stuff with the state ?*/

    return NGX_OK;
}

static void
ngx_http_upstream_send_request_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
}

static void
ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
}

static ngx_int_t
ngx_http_upstream_send_request_body(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t                     rc;
    ngx_chain_t                  *cl;
    ngx_connection_t             *c;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;

    c = u->peer.connection;

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);


    cl = ajp_data_msg_send_body(r, alcf->max_ajp_data_packet_size_conf, &a->body);

    if (cl) {
        c->log->action = "sending request body again to upstream";

        rc = ngx_output_chain(&u->output, cl);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        if (rc == NGX_AGAIN) {
            ngx_add_timer(c->write, u->conf->send_timeout);

            if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) {
                return NGX_ERROR;
            }

            u->write_event_handler = ngx_http_upstream_send_request_handler;

            return NGX_AGAIN;
        }

        /* rc == NGX_OK */

        if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
            if (ngx_tcp_push(c->fd) == NGX_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,
                        ngx_tcp_push_n " failed");
                return NGX_ERROR;
            }

            c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
        }

        ngx_add_timer(c->read, u->conf->read_timeout);

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        u->write_event_handler = ngx_http_upstream_dummy_handler;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_ajp_process_header(ngx_http_request_t *r)
{
    ngx_int_t                     type, rc;
    ajp_msg_t                    *msg;
    ngx_http_upstream_t          *u;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;


    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a == NULL || alcf == NULL) {
        return NGX_ERROR;
    }

    u = r->upstream;

    if (NGX_OK != ajp_msg_create_without_buffer(r->pool, &msg)) {
        return NGX_ERROR;
    }

    msg->buf = &u->buffer;

    while (1) {
        msg->buf->start = msg->buf->pos;
        ajp_msg_reset(msg);

        type = ajp_parse_type(r, msg);

        switch (type) {
            case CMD_AJP13_GET_BODY_CHUNK:

                /*move the buffer*/
                ajp_msg_get_uint8(msg, (u_char *)&type);
                rc = ngx_http_upstream_send_request_body(r, u);

                if (rc != NGX_OK) {
                    return rc;
                }

                break;

            case CMD_AJP13_SEND_HEADERS:
                /*xxx: have not think about the uncomplete headline*/
                rc = ajp_parse_header(r, alcf, msg);
                if (rc != NGX_OK) {
                    return rc;
                }

                break;

            case CMD_AJP13_SEND_BODY_CHUNK:
                break;

            case CMD_AJP13_END_RESPONSE:
                break;

            default:
                break;
        }
    }


    return NGX_OK;
}

static ngx_int_t
ngx_http_ajp_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    return NGX_OK;
}

static void
ngx_http_ajp_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http ajp request");
    return;
}


static void
ngx_http_ajp_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http ajp request");

    return;
}

