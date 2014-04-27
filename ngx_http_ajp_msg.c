#include "ngx_http_ajp.h"

extern volatile ngx_cycle_t  *ngx_cycle;


static ngx_int_t
ajp_msg_check_header(ajp_msg_t *msg)
{
    u_char *head = msg->buf->pos;

    if (!((head[0] == 0x41 && head[1] == 0x42) ||
          (head[0] == 0x12 && head[1] == 0x34)))
    {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ajp_check_msg_header() got bad signature %02Xd%02Xd",
                      head[0], head[1]);

        return NGX_ERROR;
    }

   return NGX_OK;
}


ngx_int_t
ajp_msg_is_zero_length(u_char *head)
{

    if (head[0] == 0x41 && head[1] == 0x42 &&
        head[3] == 0x00 && head[4] == 0x00)
    {
        return 1;
    }

    return 0;
}


ngx_int_t
ajp_msg_parse_begin(ajp_msg_t *msg)
{
    ngx_buf_t *buf = msg->buf;

    if (buf->last <= buf->pos + AJP_HEADER_LEN) {
        return NGX_ERROR;
    }

    if (ajp_msg_check_header(msg) != NGX_OK) {
        return NGX_ERROR;
    }

    buf->pos += AJP_HEADER_LEN;

    return NGX_OK;
}


ngx_int_t
ajp_msg_reset(ajp_msg_t *msg)
{
    ngx_buf_t *buf = msg->buf;

    if (buf->end > buf->start + AJP_HEADER_LEN) {
        buf->pos = buf->last = buf->start + AJP_HEADER_LEN;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ajp_msg_t *
ajp_msg_reuse(ajp_msg_t *msg)
{
    memset(msg, 0, sizeof(ajp_msg_t));

    return msg;
}


ngx_int_t
ajp_msg_end(ajp_msg_t *msg)
{
    size_t     len;
    ngx_buf_t *buf;

    buf = msg->buf;
    len = buf->last - buf->start - AJP_HEADER_LEN;

    if (msg->server_side) {
        buf->start[0] = 0x41;
        buf->start[1] = 0x42;
    } else {
        buf->start[0] = 0x12;
        buf->start[1] = 0x34;
    }

    buf->start[2] = (u_char)((len >> 8) & 0xFF);
    buf->start[3] = (u_char)(len & 0xFF);

    buf->pos = buf->start;

    return NGX_OK;
}


ngx_int_t
ajp_log_overflow(ajp_msg_t *msg, const char *context)
{
    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "%s(): BufferOverflowException pos:%p, last:%p, end:%p",
                  context, msg->buf->pos, msg->buf->last, msg->buf->end);

    return AJP_EOVERFLOW;
}


ngx_int_t
ajp_msg_append_uint32(ajp_msg_t *msg, uint32_t value)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 4) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint32");
    }

    *buf->last++ = (u_char)((value >> 24) & 0xFF);
    *buf->last++ = (u_char)((value >> 16) & 0xFF);
    *buf->last++ = (u_char)((value >> 8) & 0xFF);
    *buf->last++ = (u_char)(value & 0xFF);

    return NGX_OK;
}


ngx_int_t
ajp_msg_append_uint16(ajp_msg_t *msg, uint16_t value)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 2) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint16");
    }

    *buf->last++ = (u_char)((value >> 8) & 0xFF);
    *buf->last++ = (u_char)(value & 0xFF);

    return NGX_OK;
}


ngx_int_t
ajp_msg_append_uint8(ajp_msg_t *msg, u_char value)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 1) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint8");
    }

    *buf->last++ = value;

    return NGX_OK;
}


ngx_int_t
ajp_msg_append_string(ajp_msg_t *msg, ngx_str_t *value)
{
    ngx_buf_t *buf;

    if (value == NULL) {
        return(ajp_msg_append_uint16(msg, 0xFFFF));
    }

    buf = msg->buf;

    if ((buf->last + 2 + value->len + 1) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_cvt_string");
    }

    ajp_msg_append_uint16(msg, (uint16_t) value->len);

    ngx_memcpy(buf->last, value->data, value->len);
    buf->last  += value->len;

    *buf->last++ = '\0';

    return NGX_OK;
}


ngx_int_t
ajp_msg_get_uint32(ajp_msg_t *msg, uint32_t *rvalue)
{
    uint32_t   value;
    ngx_buf_t *buf;

    buf = msg->buf;
    if ((buf->pos + 4) > buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint32");
    }

    value  = ((*buf->pos++ & 0xFF) << 24);
    value |= ((*buf->pos++ & 0xFF) << 16);
    value |= ((*buf->pos++ & 0xFF) << 8);
    value |= ((*buf->pos++ & 0xFF));

    *rvalue = value;

    return NGX_OK;
}


ngx_int_t
ajp_msg_get_uint16(ajp_msg_t *msg, uint16_t *rvalue)
{
    uint16_t value;
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->pos + 2) > buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint16");
    }

    value = ((*buf->pos++ & 0xFF) << 8);
    value += ((*buf->pos++) & 0xFF);

    *rvalue = value;

    return NGX_OK;
}


ngx_int_t
ajp_msg_peek_uint16(ajp_msg_t *msg, uint16_t *rvalue)
{
    uint16_t value;
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->pos + 2) > buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_peek_uint16");
    }

    value = ((*buf->pos & 0xFF) << 8);
    value += ((*buf->pos + 1) & 0xFF);

    *rvalue = value;

    return NGX_OK;
}


ngx_int_t
ajp_msg_peek_uint8(ajp_msg_t *msg, u_char *rvalue)
{
    if ((msg->buf->pos + 1) > msg->buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_peek_uint8");
    }

    *rvalue = *msg->buf->pos;

    return NGX_OK;
}


ngx_int_t
ajp_msg_get_uint8(ajp_msg_t *msg, u_char *rvalue)
{
    if ((msg->buf->pos + 1) > msg->buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint8");
    }

    *rvalue = *msg->buf->pos++;

    return NGX_OK;
}


ngx_int_t
ajp_msg_get_string(ajp_msg_t *msg, ngx_str_t *value)
{
    u_char    *start;
    uint16_t   size;
    ngx_int_t  status;
    ngx_buf_t *buf;

    buf = msg->buf;
    status = ajp_msg_get_uint16(msg, &size);

    start = buf->pos;

    if ((status != NGX_OK) || (start + size + 1 > buf->last)) {
        return ajp_log_overflow(msg, "ajp_msg_get_string");
    }

    buf->pos += (size_t)size;
    buf->pos++;   /* a String in AJP is NULL terminated */

    value->data = start;
    value->len = size;

    return NGX_OK;
}


ngx_int_t
ajp_msg_create(ngx_pool_t *pool, size_t size, ajp_msg_t **rmsg)
{
    ajp_msg_t *msg;

    msg = (ajp_msg_t *)ngx_pcalloc(pool, sizeof(ajp_msg_t));
    if (msg == NULL) {
        return NGX_ERROR;
    }

    msg->server_side = 0;

    msg->buf = ngx_create_temp_buf(pool, size);

    if (msg->buf == NULL) {
        return NGX_ERROR;
    }

    *rmsg = msg;

    return NGX_OK;
}


ngx_int_t
ajp_msg_create_buffer(ngx_pool_t *pool, size_t size, ajp_msg_t *msg)
{
    msg->server_side = 0;

    msg->buf = ngx_create_temp_buf(pool, size);
    if (msg->buf == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ajp_msg_create_without_buffer(ngx_pool_t *pool, ajp_msg_t **rmsg)
{
    ajp_msg_t *msg;

    msg = (ajp_msg_t *)ngx_pcalloc(pool, sizeof(ajp_msg_t));
    if (msg == NULL) {
        return NGX_ERROR;
    }

    msg->server_side = 0;

    *rmsg = msg;

    return NGX_OK;
}


ngx_int_t
ajp_alloc_data_msg(ngx_pool_t *pool, ajp_msg_t *msg)
{
    ngx_int_t rc;

    if ((rc = ajp_msg_create_buffer(pool, AJP_HEADER_SZ + 1, msg)) != NGX_OK) {
        return rc;
    }

    ajp_msg_reset(msg);

    return NGX_OK;
}


ngx_int_t
ajp_data_msg_end(ajp_msg_t *msg, size_t len)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    buf->last = buf->start + AJP_HEADER_SZ;

    ajp_msg_end(msg);

    buf->start[AJP_HEADER_SZ - 2] = (u_char)((len >> 8) & 0xFF);
    buf->start[AJP_HEADER_SZ - 1] = (u_char)(len & 0xFF);

    /* len include AJP_HEADER_SIZE_LEN */
    len += AJP_HEADER_SZ_LEN;
    buf->start[AJP_HEADER_LEN - 2] = (u_char)((len >> 8) & 0xFF);
    buf->start[AJP_HEADER_LEN - 1] = (u_char)(len & 0xFF);

    return NGX_OK;
}


u_char *
ajp_msg_dump(ngx_pool_t *pool, ajp_msg_t *msg, char *err)
{
    size_t     i, len, dump;
    u_char    *rv, *p, *last;
    ngx_buf_t *buf;

    buf = msg->buf;

    dump = DUMP_LENGTH;
    if (dump >(size_t)(buf->last - buf->pos)) {
        dump = buf->last - buf->pos;
    }

    len = dump + 256;
    p = rv = ngx_pcalloc(pool, len);
    if (rv == NULL) {
        return NULL;
    }

    last = rv + len;

    p = ngx_snprintf(p, len,
            "ajp_msg_dump(): \"%s\", start:%p, pos:%p, last:%p \n"
            "dump packet: \n",
            err, buf->start, buf->pos, buf->last);

    for (i = 0; i < dump; i ++) {
        p = ngx_snprintf(p, last - p, "%02xd ", buf->pos[i]);

        if ((i+1) % 16 == 0) {
            p = ngx_snprintf(p, last - p, "\n");
        }
    }

    p = ngx_snprintf(p, last - p, "\n");

    return rv;
}


/* TODO: health check */
ngx_int_t
ajp_msg_serialize_ping(ajp_msg_t *msg)
{
    ngx_int_t rc;

    ajp_msg_reset(msg);

    if ((rc = ajp_msg_append_uint8(msg, CMD_AJP13_PING)) != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


/* TODO: health check */
ngx_int_t
ajp_msg_serialize_cping(ajp_msg_t *msg)
{
    ngx_int_t rc;

    ajp_msg_reset(msg);

    if ((rc = ajp_msg_append_uint8(msg, CMD_AJP13_CPING)) != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}
