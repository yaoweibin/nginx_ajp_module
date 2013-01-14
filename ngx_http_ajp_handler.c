
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ajp.h>
#include <ngx_http_ajp_handler.h>


static ngx_int_t ngx_http_ajp_eval(ngx_http_request_t *r,
    ngx_http_ajp_loc_conf_t *alcf);
#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_ajp_create_key(ngx_http_request_t *r);
#endif
static ngx_int_t ngx_http_ajp_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ajp_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ajp_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_ajp_input_filter_init(void *data);
static ngx_int_t ngx_http_ajp_input_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static void ngx_http_ajp_abort_request(ngx_http_request_t *r);
static void ngx_http_ajp_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_upstream_send_request_body(ngx_http_request_t *r, 
    ngx_http_upstream_t *u);
static ngx_chain_t *ajp_data_msg_send_body(ngx_http_request_t *r, size_t max_size,
    ngx_chain_t **body);
static void ngx_http_upstream_send_request_body_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u);

static ngx_int_t ngx_http_ajp_move_buffer(ngx_http_request_t *r, ngx_buf_t *buf,
        u_char *pos, u_char *last);
static ngx_int_t ngx_http_ajp_process_packet_header(ngx_http_request_t *r,
        ngx_http_ajp_ctx_t *a, ngx_buf_t *buf);
static void ngx_http_ajp_end_response(ngx_http_request_t *r, int reuse);


ngx_int_t
ngx_http_ajp_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_upstream_t      *u;
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

    a->state = ngx_http_ajp_st_init_state;
    a->pstate = ngx_http_ajp_st_init_state;

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
    u->input_filter_init = ngx_http_ajp_input_filter_init;

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
    ngx_http_ajp_loc_conf_t      *alcf;

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
    ajp_msg_t                    *msg;
    ngx_chain_t                  *cl;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a == NULL || alcf == NULL) {
        return NGX_ERROR;
    }

    msg = ajp_msg_reuse(&a->msg);

    if (NGX_OK != ajp_msg_create_buffer(r->pool,
                alcf->ajp_header_packet_buffer_size_conf, msg)) {
        return NGX_ERROR;
    }

    if (NGX_OK != ajp_marshal_into_msgb(msg, r, alcf)) {
        return NGX_ERROR;
    }

    ajp_msg_end(msg);

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = msg->buf;
    cl->buf->flush = 1;

    a->state = ngx_http_ajp_st_forward_request_sent;

    if (alcf->upstream.pass_request_body) {
        a->body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

        cl->next = ajp_data_msg_send_body(r, 
                alcf->max_ajp_data_packet_size_conf, &a->body);

        if (a->body) {
            a->state = ngx_http_ajp_st_request_body_data_sending;
        }
        else {
            a->state = ngx_http_ajp_st_request_send_all_done;
        }

    } else {
        a->state = ngx_http_ajp_st_request_send_all_done;
        r->upstream->request_bufs = cl;
        cl->next = NULL;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ajp_reinit_request(ngx_http_request_t *r)
{
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a == NULL || alcf == NULL) {
        return NGX_ERROR;
    }

    a->state = ngx_http_ajp_st_init_state;
    a->pstate = ngx_http_ajp_pst_init_state;
    a->length = 0;
    a->extra_zero_byte = 0;

    ajp_msg_reuse(&a->msg);

    a->body = NULL;

    return NGX_OK;
}


static ngx_list_t *
ngx_list_reinit(ngx_list_t *list)
{
    ngx_list_part_t  *head;

    head = &list->part;

    if (head->nelts > 0) {
        list->last = head;

        head->nelts = 0;
        head->next = NULL;
    }

    return list;
}


static ngx_int_t
ngx_http_ajp_process_header(ngx_http_request_t *r)
{
    uint16_t                      length;
    u_char                       *pos, *last, type, reuse;
    ngx_int_t                     rc;
    ngx_buf_t                    *buf;
    ajp_msg_t                    *msg;
    ngx_http_upstream_t          *u;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;


    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a == NULL || alcf == NULL) {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "ngx_http_ajp_process_header: state(%d)", a->state);

    u = r->upstream;

    msg = ajp_msg_reuse(&a->msg);
        
    buf = msg->buf = &u->buffer;

    while (buf->pos < buf->last) {

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "ngx_http_ajp_process_header: parse response, pos:%p, last:%p", 
                buf->pos, buf->last);

        /* save the position for returning NGX_AGAIN */
        pos = buf->pos;
        last = buf->last;

        if (ngx_buf_size(msg->buf) < AJP_HEADER_LEN + 1) {
            return ngx_http_ajp_move_buffer(r, buf, pos, last);
        }

        rc = ajp_msg_parse_begin(msg);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_ajp_process_header: bad header\n" 
                    "%s",
                    ajp_msg_dump(r->pool, msg, "bad header"));

            return NGX_ERROR;
        }

        rc = ajp_msg_get_uint8(msg, (u_char *)&type);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        switch (type) {
            case CMD_AJP13_GET_BODY_CHUNK:

                rc = ajp_msg_get_uint16(msg, &length);
                if (rc == AJP_EOVERFLOW) {
                    return ngx_http_ajp_move_buffer(r, buf, pos, last);
                }

                rc = ngx_http_upstream_send_request_body(r, u);
                if (rc != NGX_OK) {
                    return rc;
                }

                break;

            case CMD_AJP13_SEND_HEADERS:

                rc = ajp_unmarshal_response(msg, r, alcf);

                if (rc == NGX_OK) {
                    a->state = ngx_http_ajp_st_response_parse_headers_done;
                    return NGX_OK;
                }
                else if (rc == AJP_EOVERFLOW) {
                    a->state = ngx_http_ajp_st_response_recv_headers;

                    /* reinit the headers_int list, the memory may be stale */
                    ngx_list_reinit(&u->headers_in.headers);

                    /* 
                     * It's an uncomplete AJP packet, move back to the header of packet, 
                     * and parse the header again in next call
                     * */
                    return ngx_http_ajp_move_buffer(r, buf, pos, last);
                }
                else {
                    return  NGX_ERROR;
                }

                break;

            case CMD_AJP13_SEND_BODY_CHUNK:

                buf->pos = pos;
                a->state = ngx_http_ajp_st_response_body_data_sending;

                /* input_filter function will process these data */
                return NGX_OK;

                break;

            case CMD_AJP13_END_RESPONSE:

                rc = ajp_msg_get_uint8(msg, &reuse);
                if (rc == AJP_EOVERFLOW) {
                    return ngx_http_ajp_move_buffer(r, buf, pos, last);
                }

                ngx_http_ajp_end_response(r, reuse);

                buf->last_buf = 1;
                return NGX_OK;

                break;

            default:

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "ngx_http_ajp_process_header: bad_packet_type(%d)\n" 
                        "%s",
                        type, 
                        ajp_msg_dump(r->pool, msg, "bad type"));

                return  NGX_ERROR;
        }
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_ajp_input_filter_init(void *data)
{
    ngx_http_request_t           *r = data;

    r->upstream->pipe->length = (off_t) AJP_HEADER_LEN;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_ajp_move_buffer(ngx_http_request_t *r, ngx_buf_t *buf, u_char *pos, u_char *last)
{
    /* Move the end part data to the head of buffer, reuse the buffer. */
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "ngx_http_ajp_process_header: move buffer for the ajp packet.\n");

    /*
     * The first buffer, there should have enough buffer room.
     */
    if (buf->last == buf->end) {
        buf->pos = buf->start;
        buf->last = buf->start + (last - pos);

        if (buf->last > pos ) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ngx_http_ajp_process_header: too small buffer for the ajp packet.\n");

            return NGX_ERROR;
        }

        ngx_memcpy(buf->pos, pos, last - pos);
    }
    else {
        /*
         * Back to the orginal postion.
         * */
        buf->pos = pos;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_upstream_send_request_body(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t                     rc;
    ngx_chain_t                  *cl;
    ajp_msg_t                    *msg, local_msg;
    ngx_connection_t             *c;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;

    c = u->peer.connection;

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a->state > ngx_http_ajp_st_request_body_data_sending) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "ngx_http_upstream_send_request_body: bad state(%d)", a->state);
    }

    cl = ajp_data_msg_send_body(r, alcf->max_ajp_data_packet_size_conf, &a->body);

    if (u->output.in == NULL && u->output.busy == NULL) {
        if (cl == NULL) {
            /*If there is no more data in the body (i.e. the servlet container is
              trying to read past the end of the body), the server will send back
              an "empty" packet, which is a body packet with a payload length of 0.
              (0x12,0x34,0x00,0x00) */
            msg = ajp_msg_reuse(&local_msg);

            if (ajp_alloc_data_msg(r->pool, msg) != NGX_OK) {
                return NGX_ERROR;
            }

            ajp_data_msg_end(msg, 0);

            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            cl->buf = msg->buf;
            cl->next = NULL;
        }
    }

    if (a->body) {
        a->state = ngx_http_ajp_st_request_body_data_sending;
    }
    else {
        a->state = ngx_http_ajp_st_request_send_all_done;
    }

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

        u->write_event_handler = ngx_http_upstream_send_request_body_handler;

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

    return NGX_OK;
}


ngx_chain_t *
ajp_data_msg_send_body(ngx_http_request_t *r, size_t max_size, ngx_chain_t **body)
{
    size_t                    size;
    ngx_buf_t                *b_in, *b_out;
    ngx_chain_t              *out, *cl, *in;
    ajp_msg_t                *msg;
    ngx_http_ajp_ctx_t       *a;

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);

    if (*body == NULL || a == NULL) {
        return NULL;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, 
            r->connection->log, 0, "ajp_data_msg_send_body");

    msg = ajp_msg_reuse(&a->msg);

    if (ajp_alloc_data_msg(r->pool, msg) != NGX_OK) {
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
            else if ((size_t)(b_in->file_last - b_in->file_pos) > (max_size - size)) {
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
            else if ((size_t)(b_in->last - b_in->pos) > (max_size - size)) {
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

    *body = in;
    cl->next = NULL;
    
    ajp_data_msg_end(msg, size);

    return out;
}


static void
ngx_http_upstream_send_request_body_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t rc;

    rc = ngx_http_upstream_send_request_body(r, u);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ngx_http_upstream_send_request_body error");
    }
}


static void
ngx_http_upstream_dummy_handler(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "ajp upstream dummy handler");
    return;
}


static ngx_int_t
ngx_http_ajp_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_int_t                     rc;
    ngx_buf_t                    *b, **prev;
    ngx_chain_t                  *cl;
    ngx_http_request_t           *r;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "ngx_http_ajp_input_filter: state(%d)", a->state);

    b = NULL;
    prev = &buf->shadow;

    while(buf->pos < buf->last) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
                "input filter packet, begin length: %z, buffer_size: %z",
                       a->length, ngx_buf_size(buf));

        /* This a new data packet */
        if (a->length == 0) {

            if (a->extra_zero_byte) { 
                if (*(buf->pos) == 0x00){
                    buf->pos++;
                }

                a->extra_zero_byte = 0;
            }

            rc = ngx_http_ajp_process_packet_header(r, a, buf);

            if (buf->pos == buf->last) {
                break;
            }

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_DONE) {
                break;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

        }

        /* Get a zero length packet */
        if (a->length == 0) {

            if (a->extra_zero_byte && 
                    (buf->pos < buf->last) && (*(buf->pos) == 0x00)) {
                buf->pos++;
                a->extra_zero_byte = 0;
            }

            continue;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, p->log, 0,
                "input filter packet, length:%z, buffer_size:%z",
                       a->length, ngx_buf_size(buf));

        if (p->free) {
            b = p->free->buf;
            p->free = p->free->next;

        } else {
            b = ngx_alloc_buf(p->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }
        }

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->pos = buf->pos;
        b->start = buf->start;
        b->end = buf->end;
        b->tag = p->tag;
        b->temporary = 1;
        b->recycled = 1;

        *prev = b;
        prev = &b->shadow;

        cl = ngx_alloc_chain_link(p->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;

        if (p->in) {
            *p->last_in = cl;
        } else {
            p->in = cl;
        }
        p->last_in = &cl->next;

        /* STUB */ b->num = buf->num;

        if (buf->pos + a->length < buf->last) {
            buf->pos += a->length;
            b->last = buf->pos;

            a->length = 0;
        }
        else {
            a->length -= buf->last - buf->pos;
            buf->pos = buf->last;
            b->last = buf->last;
        }

        if (b->pos == b->last) {
            b->sync = 1;
        }

        if ((a->length == 0) && a->extra_zero_byte 
                && (buf->pos < buf->last) && (*(buf->pos) == 0x00)) {

            /* The last byte of this message always seems to be
               0x00 and is not part of the chunk. */
            buf->pos++;
            a->extra_zero_byte = 0;
        }

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf #%d %p size: %z", b->num, b->pos, b->last - b->pos);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
            "free buf %p %z", buf->pos, ngx_buf_size(buf));

    if (alcf->keep_conn) {
        /* set p->length, minimal amount of data we want to see */
        if (!a->length) {
            p->length = 1;
        } else {
            p->length = a->length;
        }

        if (p->upstream_done) {
            p->length = 0;
        }
    }

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, ngx_buf_size(buf));

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, buf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_ajp_process_packet_header(ngx_http_request_t *r, 
        ngx_http_ajp_ctx_t *a, ngx_buf_t *buf)
{
    int                            reuse;
    u_char                         ch;
    ngx_http_ajp_packet_state_e    state;

    state = a->pstate;

    while(buf->pos < buf->last) {

        ch = *buf->pos++;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http ajp packet header pstate: %d, byte: %02Xd", state, ch);

        switch (state) {

        case ngx_http_ajp_pst_init_state:
            if (ch != 0x41) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected AJP "
                              "preamble1: %d", ch);

                return NGX_ERROR;
            }

            state = ngx_http_ajp_pst_preamble1;
            break;

        case ngx_http_ajp_pst_preamble1:
            if (ch != 0x42) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected AJP "
                              "preamble2: %d", ch);

                return NGX_ERROR;
            }

            state = ngx_http_ajp_pst_preamble2;
            break;

        case ngx_http_ajp_pst_preamble2:
            /* Not record the payload length */
            state = ngx_http_ajp_pst_payload_length_hi;
            break;

        case ngx_http_ajp_pst_payload_length_hi:
            state = ngx_http_ajp_pst_payload_length_lo;
            break;

        case ngx_http_ajp_pst_payload_length_lo:
            if (ch == CMD_AJP13_SEND_BODY_CHUNK) {
                state = ngx_http_ajp_pst_data_length_hi;
            }
            else if (ch == CMD_AJP13_END_RESPONSE) {
                state = ngx_http_ajp_pst_end_response;
            }
            else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "upstream sent unexpected AJP "
                        "type: %d", ch);

                return NGX_ERROR;
            }

            break;

        case ngx_http_ajp_pst_end_response:
            if (ch == 0x01) {
                reuse = 1;
            }
            else {
                reuse = 0;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "ngx_http_ajp_end_response: reuse=%d", reuse);

            ngx_http_ajp_end_response(r, reuse); 
            a->pstate = ngx_http_ajp_pst_init_state;

            return NGX_DONE;

        case ngx_http_ajp_pst_data_length_hi:
            a->length_hi = ch;
            state = ngx_http_ajp_pst_data_length_lo;

            break;

        case ngx_http_ajp_pst_data_length_lo:
            a->length = (a->length_hi << 8) + ch; 

            a->pstate = ngx_http_ajp_pst_init_state;
            a->length_hi = 0x00;
            a->extra_zero_byte = 1;

            return NGX_OK;
        }
    }

    a->pstate = state;

    return NGX_AGAIN;
}


static void
ngx_http_ajp_end_response(ngx_http_request_t *r, int reuse) 
{
    ngx_event_pipe_t             *p;
    ngx_http_ajp_ctx_t           *a;
    ngx_http_ajp_loc_conf_t      *alcf;

    a = ngx_http_get_module_ctx(r, ngx_http_ajp_module);
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_ajp_module);

    if (a == NULL || alcf == NULL) {
        return;
    }

    p = r->upstream->pipe;

    a->ajp_reuse = reuse;
    if (alcf->keep_conn && reuse) {
        r->upstream->keepalive = 1;
    }
    p->upstream_done = 1;
    a->state = ngx_http_ajp_st_response_end;
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

