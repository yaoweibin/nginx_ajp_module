
/* Main source copied from Apache's mod_ajp_proxy */

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

#include "ngx_http_ajp.h"

extern volatile ngx_cycle_t  *ngx_cycle;

/**
 * Dump up to the first 16 bytes on an AJP Message
 *
 * @param pool      pool to allocate from
 * @param msg       AJP Message to dump
 * @param err       error string to display
 * @return          dump message
 */
u_char * ajp_msg_dump(ngx_pool_t *pool, ajp_msg_t *msg, u_char *err)
{
    size_t  i, len;
    u_char   *rv, *p, *last;
    size_t  bl = 8192;
    ngx_buf_t *buf;

    buf = msg->buf;

    len = buf->last - buf->start;
    /* Display only first 16 bytes */
    if (len > 16) {
        len = 16;
    }

    rv = ngx_palloc(pool, bl);
    if (rv == NULL) {
        return NULL;
    }

    last = rv + bl;
    p = rv;

    p = ngx_snprintf(p, last - p, 
            "ajp_msg_dump(): \"%s\", start:%p, pos:%p, last:%p, \ndump line: ",
            err, buf->start, buf->pos, buf->last);

    for (i = 0; i < len; i ++) {
        p = ngx_snprintf(p, last - p, "%02xd ", buf->start[i]);
    }

    return rv;
}

/**
 * Check a new AJP Message by looking at signature and return its size
 *
 * @param msg       AJP Message to check
 * @param len       Pointer to returned len
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_check_header(ajp_msg_t *msg, size_t *len)
{
    u_char *head = msg->buf->start;
    size_t msglen;

    if (!((head[0] == 0x41 && head[1] == 0x42) ||
          (head[0] == 0x12 && head[1] == 0x34))) {

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_check_msg_header() got bad signature %Xd%Xd",
                head[0], head[1]);

        return AJP_EBAD_SIGNATURE;
    }

    msglen  = ((head[2] & 0xff) << 8);
    msglen += (head[3] & 0xFF);

    if (msglen > (size_t) (msg->buf->end - msg->buf->start)) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ajp_check_msg_header() incoming message is "
                     "too big %z, max is %z",
                     msglen, (msg->buf->end - msg->buf->start));
        return AJP_ETOBIG;
    }

    msg->buf->last = msg->buf->start + msglen + AJP_HEADER_LEN;
    msg->buf->pos = msg->buf->start + AJP_HEADER_LEN;
    *len     = msglen;

    return NGX_OK;
}

ngx_int_t ajp_parse_begin(ajp_msg_t *msg)
{
    ngx_buf_t *buf = msg->buf;

    if (buf->end > buf->pos + AJP_HEADER_LEN) {
        buf->pos += AJP_HEADER_LEN;
    }
    else {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * Reset an AJP Message
 *
 * @param msg       AJP Message to reset
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_reset(ajp_msg_t *msg)
{
    ngx_buf_t *buf = msg->buf;

    if (buf->end > buf->start + AJP_HEADER_LEN) {
        buf->pos = buf->last = buf->start + AJP_HEADER_LEN;
    }

    return NGX_OK;
}

/**
 * Reuse an AJP Message
 *
 * @param msg       AJP Message to reuse
 * @return          NGX_OK or error
 */
ajp_msg_t * ajp_msg_reuse(ajp_msg_t *msg)
{
    memset(msg, 0, sizeof(ajp_msg_t));
    msg->header_len = AJP_HEADER_LEN;

    return msg;
}

/**
 * Mark the end of an AJP Message
 *
 * @param msg       AJP Message to end
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_end(ajp_msg_t *msg)
{
    size_t     len;
    ngx_buf_t *buf;

    buf = msg->buf;
    len = buf->last - buf->start - AJP_HEADER_LEN;

    if (msg->server_side) {
        buf->start[0] = 0x41;
        buf->start[1] = 0x42;
    }
    else {
        buf->start[0] = 0x12;
        buf->start[1] = 0x34;
    }

    buf->start[2] = (u_char)((len >> 8) & 0xFF);
    buf->start[3] = (u_char)(len & 0xFF);

    buf->pos = buf->start;

    return NGX_OK;
}

static inline int ajp_log_overflow(ajp_msg_t *msg, const char *context)
{
    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "%s(): BufferOverflowException pos:%p, last:%p, end:%p",
            context, msg->buf->pos, msg->buf->last, msg->buf->end);

    return AJP_EOVERFLOW;
}

/**
 * Add an unsigned 32bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_uint32(ajp_msg_t *msg, uint32_t value)
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

/**
 * Add an unsigned 16bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_uint16(ajp_msg_t *msg, uint16_t value)
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

/**
 * Add an unsigned 8bits value to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     value to add to AJP Message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_uint8(ajp_msg_t *msg, u_char value)
{
    ngx_buf_t *buf;

    buf = msg->buf;

    if ((buf->last + 1) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_uint8");
    }

    *buf->last++ = value;

    return NGX_OK;
}

/**
 *  Add a String in AJP message, and transform the String in ASCII
 *  if convert is set and we're on an EBCDIC machine
 *
 * @param msg       AJP Message to get value from
 * @param value     Pointer to String
 * @param convert   When set told to convert String to ASCII
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_string_ex(ajp_msg_t *msg, ngx_str_t *value,
                                      int convert)
{
    ngx_buf_t *buf;

    if (value == NULL) {
        return(ajp_msg_append_uint16(msg, 0xFFFF));
    }

    buf = msg->buf;

    if ((buf->last + 2 + value->len + 1) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_cvt_string");
    }

    /* ignore error - we checked once */
    ajp_msg_append_uint16(msg, (uint16_t) value->len);

    /* We checked for space !!  */
    ngx_memcpy(buf->last, value->data, value->len); 
    buf->last  += value->len;
    /* including \0 */
    *buf->last++ = '\0';

    /*if (convert)   *//* convert from EBCDIC if needed */
        /*ajp_xlate_to_ascii((char *)msg->buf + msg->len, len + 1);*/

    return NGX_OK;
}

/**
 * Add a Byte array to AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param value     Pointer to Byte array
 * @param valuelen  Byte array len
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_append_bytes(ajp_msg_t *msg, const u_char *value,
                                  size_t valuelen)
{
    ngx_buf_t *buf;

    if (valuelen == 0) {
        return NGX_OK; /* Shouldn't we indicate an error ? */
    }

    buf = msg->buf;
    if ((buf->last + valuelen) > buf->end) {
        return ajp_log_overflow(msg, "ajp_msg_append_bytes");
    }

    /* We checked for space !!  */
    ngx_memcpy(buf->last, value, valuelen);
    buf->last  += valuelen;

    return NGX_OK;
}

/**
 * Get a 32bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_uint32(ajp_msg_t *msg, uint32_t *rvalue)
{
    uint32_t value;
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


/**
 * Get a 16bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_uint16(ajp_msg_t *msg, uint16_t *rvalue)
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

/**
 * Peek a 16bits unsigned value from AJP Message, position in message
 * is not updated
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_peek_uint16(ajp_msg_t *msg, uint16_t *rvalue)
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

/**
 * Peek a 8bits unsigned value from AJP Message, position in message
 * is not updated
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_peek_uint8(ajp_msg_t *msg, u_char *rvalue)
{
    if ((msg->buf->pos + 1) > msg->buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_peek_uint8");
    }

    *rvalue = *msg->buf->pos;

    return NGX_OK;
}

/**
 * Get a 8bits unsigned value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_uint8(ajp_msg_t *msg, u_char *rvalue)
{

    if ((msg->buf->pos + 1) > msg->buf->last) {
        return ajp_log_overflow(msg, "ajp_msg_get_uint8");
    }

    *rvalue = *(u_char *)(msg->buf->pos);

    msg->buf->pos = msg->buf->pos + 1;

    return NGX_OK;
}


/**
 * Get a String value from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_string(ajp_msg_t *msg, ngx_str_t *value)
{
    uint16_t size;
    u_char  *start;
    ngx_int_t status;
    ngx_buf_t *buf;

    buf = msg->buf;
    status = ajp_msg_get_uint16(msg, &size);

    start = buf->pos;

    if ((status != NGX_OK) || (start + size + 1 > buf->last)) {
        return ajp_log_overflow(msg, "ajp_msg_get_string");
    }

    buf->pos += (size_t)size;
    buf->pos++;      /* a String in AJP is NULL terminated */

    value->data = start;
    value->len = size;

    return NGX_OK;
}


/**
 * Get a Byte array from AJP Message
 *
 * @param msg       AJP Message to get value from
 * @param rvalue    Pointer where value will be returned
 * @param rvalueLen Pointer where Byte array len will be returned
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_get_bytes(ajp_msg_t *msg, u_char **rvalue,
                               size_t *rvalue_len)
{
    uint16_t size;
    u_char *start;
    ngx_int_t status;
    ngx_buf_t *buf;

    buf = msg->buf;

    status = ajp_msg_get_uint16(msg, &size);
    /* save the current position */
    start = buf->pos;

    if ((status != NGX_OK) || (size + start > buf->last)) {
        return ajp_log_overflow(msg, "ajp_msg_get_bytes");
    }
    buf->pos += (size_t)size;   /* only bytes, no trailer */

    *rvalue     = start;
    *rvalue_len = size;

    return NGX_OK;
}


/**
 * Create an AJP Message from pool
 *
 * @param pool      memory pool to allocate AJP message from
 * @param size      size of the buffer to create
 * @param rmsg      Pointer to newly created AJP message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_create(ngx_pool_t *pool, size_t size, ajp_msg_t **rmsg)
{
    ajp_msg_t *msg = (ajp_msg_t *)ngx_pcalloc(pool, sizeof(ajp_msg_t));

    if (!msg) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_msg_create(): can't allocate AJP message memory");
        return NGX_ERROR;
    }

    msg->server_side = 0;

    msg->buf = ngx_create_temp_buf(pool, size);

    if (msg->buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ajp_msg_create(): can't allocate AJP message memory");
        return NGX_ERROR;
    }

    msg->header_len = AJP_HEADER_LEN;
    *rmsg = msg;

    return NGX_OK;
}

ngx_int_t ajp_msg_create_buffer(ngx_pool_t *pool, size_t size, ajp_msg_t *msg)
{
    msg->server_side = 0;

    msg->buf = ngx_create_temp_buf(pool, size);

    if (msg->buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "ajp_msg_create_buffer(): can't allocate AJP message buffer");
        return NGX_ERROR;
    }

    msg->header_len = AJP_HEADER_LEN;

    return NGX_OK;
}

/**
 * Create an AJP Message from pool without buffer
 *
 * @param pool      memory pool to allocate AJP message from
 * @param rmsg      Pointer to newly created AJP message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_create_without_buffer(ngx_pool_t *pool, ajp_msg_t **rmsg)
{
    ajp_msg_t *msg = (ajp_msg_t *)ngx_pcalloc(pool, sizeof(ajp_msg_t));

    if (!msg) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "ajp_msg_create_without_buffer(): can't allocate AJP message memory");
        return NGX_ERROR;
    }

    msg->server_side = 0;

    msg->header_len = AJP_HEADER_LEN;
    *rmsg = msg;

    return NGX_OK;
}

/**
 * Recopy an AJP Message to another
 *
 * @param smsg      source AJP message
 * @param dmsg      destination AJP message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_copy(ajp_msg_t *smsg, ajp_msg_t *dmsg)
{
    if (dmsg == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                     "ajp_msg_copy(): destination msg is null");
        return AJP_EINVAL;
    }

    /*TODO*/

    return NGX_OK;
}

/*
 * Allocate a msg to send data
 */
ngx_int_t  ajp_alloc_data_msg(ngx_pool_t *pool, ajp_msg_t *msg)
{
    ngx_int_t rc;

    if ((rc = ajp_msg_create_buffer(pool, AJP_HEADER_SZ + 1, msg)) != NGX_OK) {
        return rc;
    }

    ajp_msg_reset(msg);

    return NGX_OK;
}


ngx_int_t  ajp_data_msg_end(ajp_msg_t *msg, size_t len)
{
    ngx_buf_t *buf;

    buf = msg->buf;

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

/**
 * Serialize in an AJP Message a PING command
 *
 * +-----------------------+
 * | PING CMD (1 byte)     |
 * +-----------------------+
 *
 * @param smsg      AJP message to put serialized message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_serialize_ping(ajp_msg_t *msg)
{
    ngx_int_t rc;

    ajp_msg_reset(msg);

    if ((rc = ajp_msg_append_uint8(msg, CMD_AJP13_PING)) != NGX_OK)
        return rc;

    return NGX_OK;
}

/**
 * Serialize in an AJP Message a CPING command
 *
 * +-----------------------+
 * | CPING CMD (1 byte)    |
 * +-----------------------+
 *
 * @param smsg      AJP message to put serialized message
 * @return          NGX_OK or error
 */
ngx_int_t ajp_msg_serialize_cping(ajp_msg_t *msg)
{
    ngx_int_t rc;

    ajp_msg_reset(msg);

    if ((rc = ajp_msg_append_uint8(msg, CMD_AJP13_CPING)) != NGX_OK)
        return rc;

    return NGX_OK;
}
