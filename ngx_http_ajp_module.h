
#ifndef _NGX_AJP_MODULE_H_INCLUDED_
#define _NGX_AJP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_conf_t       upstream;

    size_t                         ajp_header_packet_buffer_size_conf;
    size_t                         max_ajp_data_packet_size_conf;

    ngx_array_t                   *ajp_lengths;
    ngx_array_t                   *ajp_values;

    ngx_flag_t                     keep_conn;

#if (NGX_HTTP_CACHE)
    ngx_http_complex_value_t       cache_key;
#endif

} ngx_http_ajp_loc_conf_t;


extern ngx_module_t  ngx_http_ajp_module;


#endif /* _NGX_AJP_MODULE_H_INCLUDED_ */
