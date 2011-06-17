
#ifndef _NGX_AJP_HANDLER_H_INCLUDED_
#define _NGX_AJP_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ajp_module.h>
#include <ngx_http_ajp.h>


typedef enum {
    ngx_http_ajp_st_init_state = 0,
    ngx_http_ajp_st_forward_request_sent,
    ngx_http_ajp_st_request_body_data_sending,
    ngx_http_ajp_st_request_send_all_done,
    ngx_http_ajp_st_response_recv_headers,
    ngx_http_ajp_st_response_parse_headers_done,
    ngx_http_ajp_st_response_headers_sent,
    ngx_http_ajp_st_response_body_data_sending,
    ngx_http_ajp_st_response_end
} ngx_http_ajp_state_e;

typedef enum {
    ngx_http_ajp_pst_init_state = 0,
    ngx_http_ajp_pst_preamble1,
    ngx_http_ajp_pst_preamble2,
    ngx_http_ajp_pst_payload_length_hi,
    ngx_http_ajp_pst_payload_length_lo,
    ngx_http_ajp_pst_end_response,
    ngx_http_ajp_pst_data_length_hi,
    ngx_http_ajp_pst_data_length_lo
} ngx_http_ajp_packet_state_e;

typedef struct {
    ngx_http_ajp_state_e           state;
    ngx_http_ajp_packet_state_e    pstate;

    u_char                         length_hi;
    /* record the response body chunk packet's length */
    size_t                         length;

    /* extra zero byte in each ajp data packet */
    ngx_uint_t                     extra_zero_byte;

    /* reuse in sending request and receiving response */
    ajp_msg_t                      msg;

    /* save the left request body buffers */
    ngx_chain_t                   *body;

    ngx_uint_t                     ajp_reuse; /* unsigned :1 */

} ngx_http_ajp_ctx_t;


ngx_int_t ngx_http_ajp_handler(ngx_http_request_t *r);


#endif /* _NGX_AJP_HANDLER_H_INCLUDED_ */
