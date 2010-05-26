
#ifndef _NGX_AJP_HANDLER_H_INCLUDED_
#define _NGX_AJP_HANDLER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_ajp_module.h>

typedef struct {
    /*ngx_http_ajp_state_e           state;*/
    u_char                        *pos;
    u_char                        *last;
    ngx_uint_t                     type;
    size_t                         length;
    size_t                         padding;

    ngx_uint_t                     ajp_stdout; /* unsigned :1 */

    ngx_str_t                      script_name;
    ngx_str_t                      path_info;
} ngx_http_ajp_ctx_t;

ngx_int_t ngx_http_ajp_handler(ngx_http_request_t *r);

#endif /* _NGX_AJP_HANDLER_H_INCLUDED_ */
