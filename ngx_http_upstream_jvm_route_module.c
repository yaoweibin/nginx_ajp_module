

/*
 * Copyright (C) Weibin Yao
 * Email: yaoweibin@gmail.com
 * Version: $Id: ngx_http_upstream_jvm_route_module.c 31 2009-12-07 06:14:51Z yaoweibin $
 *
 * Based on the upstream_round_robin and upstream_fair momdule.
 *
 * This module can be distributed under the same terms as Nginx itself.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define SHM_NAME_LEN 256

typedef struct {
    ngx_array_t                     *values;
    ngx_array_t                     *lengths;

    ngx_str_t                        session_cookie;
    ngx_str_t                        session_url;

    unsigned                         reverse:1; 
} ngx_http_upstream_jvm_route_srv_conf_t;

typedef struct {
    ngx_str_t shm_name;
} ngx_http_upstream_jvm_route_loc_conf_t;

typedef struct ngx_http_upstream_jvm_route_peers_s ngx_http_upstream_jvm_route_peers_t;

typedef struct {
    ngx_uint_t                          nreq; /* active requests to the peer */
    ngx_uint_t                          total_req;
    ngx_uint_t                          last_req_id;
    ngx_uint_t                          fails;
    ngx_uint_t                          total_fails;
    time_t                              accessed;
    ngx_int_t                           current_weight;
} ngx_http_upstream_jvm_route_shared_t;


typedef struct {
    ngx_uint_t                           generation;
    ngx_http_upstream_jvm_route_peers_t *peers; 
    ngx_uint_t                           total_nreq;
    ngx_uint_t                           total_requests;
    ngx_atomic_t                         lock;
    ngx_http_upstream_jvm_route_shared_t stats[1];
} ngx_http_upstream_jvm_route_shm_block_t;

/* ngx_spinlock is defined without a matching unlock primitive */
#define ngx_spinlock_unlock(lock)       (void) ngx_atomic_cmp_set(lock, ngx_pid, 0)

typedef struct {
    ngx_http_upstream_jvm_route_shared_t *shared;
    struct sockaddr                *sockaddr;
    socklen_t                       socklen;
    ngx_str_t                       name;

    ngx_int_t                       weight;
    ngx_uint_t                      max_fails;
    ngx_uint_t                      max_busy;
    time_t                          fail_timeout;
    ngx_uint_t                      down;          /* unsigned  down:1; */
    ngx_str_t                       srun_id;

#if (NGX_HTTP_SSL)
    ngx_ssl_session_t              *ssl_session;   /* local to a process */
#endif
} ngx_http_upstream_jvm_route_peer_t;

struct ngx_http_upstream_jvm_route_peers_s {
    /* data should be shared between processes */
    ngx_http_upstream_jvm_route_shm_block_t *shared;

    ngx_uint_t                               current;
    ngx_uint_t                               number;
    ngx_str_t                               *name;
    ngx_str_t                                shm_name;
    
    /* for backup peers support, not really used yet */
    ngx_http_upstream_jvm_route_peers_t     *next;  

    ngx_http_upstream_jvm_route_peer_t       peer[1];
};

#define NGX_PEER_INVALID (~0UL)

typedef struct {
    ngx_http_upstream_jvm_route_srv_conf_t *conf;
    ngx_http_upstream_jvm_route_peers_t    *peers;

    ngx_uint_t                              current;
    uintptr_t                              *tried;
    uintptr_t                               data;

    ngx_str_t                               cookie;

    ngx_uint_t                              index;
} ngx_http_upstream_jvm_route_peer_data_t;

static void * ngx_http_upstream_jvm_route_create_conf(ngx_conf_t *cf);
static void * ngx_http_upstream_jvm_route_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_init_jvm_route_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_jvm_route_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_jvm_route(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_jvm_route_set_status(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);
 
static ngx_int_t
ngx_http_upstream_get_jvm_route_peer(ngx_peer_connection_t *pc, void *data);
static void
ngx_http_upstream_free_jvm_route_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_upstream_jvm_route_set_session(ngx_peer_connection_t *pc, void *data);
static void
ngx_http_upstream_jvm_route_save_session(ngx_peer_connection_t *pc, void *data);
#endif

static ngx_int_t ngx_http_upstream_jvm_route_init_module(ngx_cycle_t *cycle);

static ngx_command_t  ngx_http_upstream_jvm_route_commands[] = {

    { ngx_string("jvm_route"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_jvm_route,
      0,
      0,
      NULL },

    { ngx_string("jvm_route_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_jvm_route_set_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_jvm_route_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_jvm_route_create_conf,/* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_upstream_jvm_route_create_loc_conf,  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_jvm_route_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_jvm_route_module_ctx, /* module context */
    ngx_http_upstream_jvm_route_commands,    /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    ngx_http_upstream_jvm_route_init_module, /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_uint_t ngx_http_upstream_jvm_route_generation = 0;

#define NGX_BITVECTOR_ELT_SIZE (sizeof(uintptr_t) * 8)

static ngx_int_t
ngx_http_upstream_jvm_route_init_module(ngx_cycle_t *cycle)
{
    ngx_http_upstream_jvm_route_generation++;
    return NGX_OK;
}

static uintptr_t *
ngx_bitvector_alloc(ngx_pool_t *pool, ngx_uint_t size, uintptr_t *small)
{
    ngx_uint_t nelts = (size + NGX_BITVECTOR_ELT_SIZE - 1) / NGX_BITVECTOR_ELT_SIZE;

    if (small && nelts == 1) {
        *small = 0;
        return small;
    }

    return ngx_pcalloc(pool, nelts * NGX_BITVECTOR_ELT_SIZE);
}

static ngx_int_t
ngx_bitvector_test(uintptr_t *bv, ngx_uint_t bit)
{
    ngx_uint_t                      n, m;

    n = bit / NGX_BITVECTOR_ELT_SIZE;
    m = 1 << (bit % NGX_BITVECTOR_ELT_SIZE);

    return bv[n] & m;
}

static void
ngx_bitvector_set(uintptr_t *bv, ngx_uint_t bit)
{
    ngx_uint_t                      n, m;

    n = bit / NGX_BITVECTOR_ELT_SIZE;
    m = 1 << (bit % NGX_BITVECTOR_ELT_SIZE);

    bv[n] |= m;
}

/* string1 compares with the string2 in reverse order.*/
static ngx_int_t
ngx_strncmp_r(u_char *s1, u_char *s2, size_t len1, size_t len2)
{
    if (len2 == 0 || len1 == 0) {
        return -1;
    }

    while (s1[--len1] == s2[--len2]) {
        if (len2 == 0 || len1 == 0) {
            return 0;
        }
    }

    return s1[len1] - s2[len2];
}

static ngx_int_t 
ngx_strntok(u_char *s, const char *delim, size_t len, size_t count)
{
    ngx_uint_t i, j;

    for (i = 0; i < len; i++) {
        for (j = 0; j < count; j++) {
            if (s[i] == delim[j])
                return i;
        }
    }

    return -1;
}

static u_char *
ngx_strncasestrn(u_char *s1, u_char *s2, size_t len1, size_t len2)
{
    u_char  c1, c2;
    size_t  n;

    if (len2 == 0 || len1 == 0) {
        return NULL;
    }

    c2 = *s2++;
    c2  = (c2 >= 'A' && c2 <= 'Z') ? (c2 | 0x20) : c2;

    n = len2 - 1;

    do {
        do {
            if (len1-- == 0) {
                return NULL;
            }

            c1 = *s1++;

            if (c1 == 0) {
                return NULL;
            }

            c1  = (c1 >= 'A' && c1 <= 'Z') ? (c1 | 0x20) : c1;

        } while (c1 != c2 || c1 != c2);

        if (n > len1) {
            return NULL;
        }

    } while (ngx_strncasecmp(s1, s2, n) != 0);

    return --s1;
}

static ngx_int_t
ngx_http_upstream_cmp_servers(const void *one, const void *two)
{
    ngx_http_upstream_jvm_route_peer_t  *first, *second;

    first = (ngx_http_upstream_jvm_route_peer_t *) one;
    second = (ngx_http_upstream_jvm_route_peer_t *) two;

    return (first->weight < second->weight);
}

/* Have not support the backup server yet. */
static ngx_int_t
ngx_http_upstream_init_jvm_route_rr(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_url_t                      u;
    ngx_uint_t                     i, j, n;
    ngx_http_upstream_server_t    *server;
    ngx_http_upstream_jvm_route_peers_t  *peers, *backup;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
        }

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_jvm_route_peers_t)
                              + sizeof(ngx_http_upstream_jvm_route_peer_t) * (n - 1));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peers->number = n;
        peers->name = &us->host;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                if (server[i].backup) {
                    continue;
                }

                peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peers->peer[n].socklen = server[i].addrs[j].socklen;
                peers->peer[n].name = server[i].addrs[j].name;
                peers->peer[n].srun_id = server[i].srun_id;
                peers->peer[n].max_fails = server[i].max_fails;
                peers->peer[n].max_busy = server[i].max_busy;
                peers->peer[n].fail_timeout = server[i].fail_timeout;
                peers->peer[n].down = server[i].down;
                peers->peer[n].weight = server[i].down ? 0 : server[i].weight;

                n++;
            }
        }

        us->peer.data = peers;

        ngx_sort(&peers->peer[0], (size_t) n,
                 sizeof(ngx_http_upstream_jvm_route_peer_t),
                 ngx_http_upstream_cmp_servers);

        /* backup servers */

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
        }

        if (n == 0) {
            return NGX_OK;
        }

        backup = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_jvm_route_peers_t)
                              + sizeof(ngx_http_upstream_jvm_route_peer_t) * (n - 1));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        backup->number = n;
        backup->name = &us->host;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                if (!server[i].backup) {
                    continue;
                }

                backup->peer[n].sockaddr = server[i].addrs[j].sockaddr;
                backup->peer[n].socklen = server[i].addrs[j].socklen;
                backup->peer[n].name = server[i].addrs[j].name;
                backup->peer[n].weight = server[i].weight;
                backup->peer[n].srun_id = server[i].srun_id;
                backup->peer[n].max_fails = server[i].max_fails;
                backup->peer[n].max_busy = server[i].max_busy;
                backup->peer[n].fail_timeout = server[i].fail_timeout;
                backup->peer[n].down = server[i].down;

                n++;
            }
        }

        peers->next = backup;

        ngx_sort(&backup->peer[0], (size_t) n,
                 sizeof(ngx_http_upstream_jvm_route_peer_t),
                 ngx_http_upstream_cmp_servers);

        return NGX_OK;
    }

    /* an upstream implicitly defined by proxy_pass, etc. */

    if (us->port == 0 && us->default_port == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
    u.port = (in_port_t) (us->port ? us->port : us->default_port);

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_jvm_route_peers_t)
                              + sizeof(ngx_http_upstream_jvm_route_peer_t) * (n - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->number = n;
    peers->name = &us->host;

    for (i = 0; i < u.naddrs; i++) {
        peers->peer[i].sockaddr = u.addrs[i].sockaddr;
        peers->peer[i].socklen = u.addrs[i].socklen;
        peers->peer[i].name = u.addrs[i].name;
        peers->peer[i].weight = 1;
        peers->peer[i].max_fails = 1;
        peers->peer[i].max_busy = 0;
        peers->peer[i].fail_timeout = 10;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}

static ngx_int_t 
ngx_http_upstream_jvm_route_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_uint_t                              i;
    ngx_atomic_t                           *lock;
    ngx_slab_pool_t                        *shpool;
    ngx_http_upstream_jvm_route_peers_t    *peers;
    ngx_http_upstream_jvm_route_shm_block_t *shm_block;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
            "[upstream_jvm_route] data:%p, shm_zone->data:%p", data, shm_zone->data);

    peers = shm_zone->data;
    if (peers) {

        if (data == NULL) {
            shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

            if (shm_zone->shm.exists) {
                shm_zone->data = shpool->data;
                return NGX_OK;
            }

            shm_block = ngx_slab_alloc(shpool, sizeof(*shm_block) +
                    (peers->number - 1) * sizeof(ngx_http_upstream_jvm_route_shared_t));

            if (shm_block == NULL) {
                ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                        "upstream_jvm_route_shm_size is too small!");
                return NGX_ERROR;
            }
        }
        else {
            /* kill -HUP*/
            shm_block = data;
        }

        shm_zone->data = shm_block;
        peers->shared = shm_block;

        lock = &peers->shared->lock;
        ngx_spinlock(lock, ngx_pid, 1024);

        shm_block->generation = ngx_http_upstream_jvm_route_generation + 1;
        shm_block->peers = peers;
        shm_block->total_nreq = 0;
        shm_block->total_requests = 0;

        for (i = 0; i < peers->number; i++) {
            shm_block->stats[i].nreq = 0;
            shm_block->stats[i].last_req_id = 0;
            shm_block->stats[i].total_req = 0;
            shm_block->stats[i].fails = 0;
            shm_block->stats[i].total_fails = 0;
            shm_block->stats[i].accessed = 0;
            shm_block->stats[i].current_weight = peers->peer[i].weight;

            peers->peer[i].shared = &peers->shared->stats[i];
        }

        ngx_spinlock_unlock(lock);

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
            "[upstream_jvm_route] can't find the peers!");
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_upstream_init_jvm_route(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    u_char                                 *last;
    ngx_str_t                              *shm_name;
    ngx_uint_t                              shm_size;
    ngx_shm_zone_t                         *shm_zone;
    ngx_http_upstream_jvm_route_peers_t    *peers;
    ngx_http_upstream_jvm_route_srv_conf_t *ujrscf;

    ujrscf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_jvm_route_module);

    if (ngx_http_upstream_init_jvm_route_rr(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    peers = us->peer.data;
    if (peers == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "[upstream_jvm_route] can't find the peers!");
        return NGX_ERROR;
    }
    peers->current = peers->number - 1;
    shm_name = &peers->shm_name;
    shm_name->data = ngx_palloc(cf->pool, SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }
    /*add the share memory with the generation*/
    last = ngx_snprintf(shm_name->data, SHM_NAME_LEN, "%V_%ui", peers->name, 
	    ngx_http_upstream_jvm_route_generation + 1);
    shm_name->len = last - shm_name->data;

    shm_size = sizeof(ngx_http_upstream_jvm_route_shm_block_t) +
            (peers->number - 1) * sizeof(ngx_http_upstream_jvm_route_shared_t);
    
    shm_size = ngx_align(shm_size, ngx_pagesize) + ngx_pagesize;

    shm_zone = ngx_shared_memory_add(cf, shm_name, shm_size, 
            &ngx_http_upstream_jvm_route_module);
    if (shm_zone == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "[upstream_jvm_route] upsteam:%V, shm_zone size:%ui", peers->name, shm_size);

    shm_zone->data = peers;
    shm_zone->init = ngx_http_upstream_jvm_route_init_shm_zone;

    us->peer.init = ngx_http_upstream_init_jvm_route_peer;

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_jvm_route_get_session_value(ngx_http_request_t *r,
    ngx_http_upstream_jvm_route_srv_conf_t *us, ngx_str_t *val)
{
    ngx_str_t *name, *uri;
    ngx_int_t  i; 
    size_t     offset;
    u_char    *start;

    /* session in cookie */
    if (ngx_http_script_run(r, val, us->lengths, 0, us->values) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[upstream_jvm_route] compiles the session in cookie error!");
        return NGX_ERROR;
    }

    /* session in url */
    if (val->len == 0) {

        if (us->session_url.len != 0) {
            name = &us->session_url;
        }
        else {
            name = &us->session_cookie;
        }

        uri = &r->unparsed_uri;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[upstream jvm_route] URI: \"%V\", session_name: \"%V\"", uri, name);

        start = ngx_strncasestrn(uri->data, name->data, uri->len, name->len);
        if (start != NULL) {
            start = start + name->len;
            while (*start != '=') {
                if (start >= (uri->data + uri->len)) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "upstream_jvm_route find the session in URI error!");
                    return NGX_ERROR;
                }
                start++;
            }

            start++;
            offset = start - uri->data;
            if (offset < uri->len) {
                val->data = start;

                i = ngx_strntok(start, "?&;", uri->len - offset, sizeof("?&;")-1);
                if (i > 0) {
                    val->len = i;
                }
                else {
                    val->len = uri->len - offset;
                }
            }
        }
    }

    if (val->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "[upstream_jvm_route] can't find the session in cookie or URI!");
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_init_jvm_route_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_str_t                                 val;
    ngx_http_upstream_jvm_route_peer_data_t  *jrp;
    ngx_http_upstream_jvm_route_peers_t      *jrps;
    ngx_http_upstream_jvm_route_srv_conf_t   *ujrscf;

    ujrscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_jvm_route_module);

    jrp = r->upstream->peer.data;

    if (jrp == NULL) {
        jrp = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_jvm_route_peer_data_t));
        if (jrp == NULL) {
            return NGX_ERROR;
        }

        r->upstream->peer.data = jrp;
    }

    jrps = us->peer.data;

    if (jrps == NULL || jrps->shared == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[upstream_jvm_route] peers or shm_zone data is NULL!");

        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "[upstream_jvm_route] jrps:%p, shared:%p", jrps, jrps->shared);

    jrp->tried = ngx_bitvector_alloc(r->pool, jrps->number, &jrp->data);

    if (ngx_http_upstream_jvm_route_get_session_value(r, ujrscf, &val) != NGX_OK) {
        return NGX_ERROR;
    } 

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "[upstream_jvm_route] session_cookie:\"%V\", session_url:\"%V\", session_value:\"%V\"",
            &ujrscf->session_cookie, &ujrscf->session_url, &val);

    jrp->cookie = val;
    jrp->current = jrps->current;
    jrp->peers = jrps;
    jrp->conf = ujrscf;
    jrps->shared->total_requests++;

    r->upstream->peer.get = ngx_http_upstream_get_jvm_route_peer;
    r->upstream->peer.free = ngx_http_upstream_free_jvm_route_peer;
    r->upstream->peer.tries = jrps->number;

#if (NGX_HTTP_SSL)
    r->upstream->peer.set_session =
                               ngx_http_upstream_jvm_route_set_session;
    r->upstream->peer.save_session =
                               ngx_http_upstream_jvm_route_save_session;
#endif

    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_jvm_route_try_peer( ngx_http_upstream_jvm_route_peer_data_t *jrp,
    ngx_uint_t peer_id)
{
    ngx_http_upstream_jvm_route_peer_t        *peer;

    if (ngx_bitvector_test(jrp->tried, peer_id)) {
        return NGX_BUSY;
    }

    peer = &jrp->peers->peer[peer_id];

    if (peer->max_busy != 0 && peer->shared->nreq >= peer->max_busy) {
        return NGX_BUSY;
    }

    if (!peer->down) {
        if (peer->max_fails == 0 || peer->shared->fails < peer->max_fails) {
            return NGX_OK;
        }

        if (ngx_time() - peer->shared->accessed > peer->fail_timeout) {
            peer->shared->fails = 0;
            return NGX_OK;
        }
    }

    return NGX_BUSY;
}

static ngx_int_t
ngx_http_upstream_choose_by_jvm_route(ngx_http_upstream_jvm_route_peer_data_t *jrp)
{
    ngx_uint_t                          i, n;
    ngx_uint_t                          npeers = jrp->peers->number;
    ngx_http_upstream_jvm_route_peer_t *peer;


    for (i = 0, n = jrp->current; i < npeers; i++, n = (n+1)%npeers) {
        peer = &jrp->peers->peer[n];

        if (jrp->conf->reverse) {
            if (ngx_strncmp_r(jrp->cookie.data, peer->srun_id.data,
                        jrp->cookie.len, peer->srun_id.len) == 0){
                if (ngx_http_upstream_jvm_route_try_peer(jrp, n) == NGX_OK) {
                    return n;
                }
            }
        }
        else {
            if (ngx_strncmp(jrp->cookie.data, peer->srun_id.data,
                        peer->srun_id.len) == 0){
                if (ngx_http_upstream_jvm_route_try_peer(jrp, n) == NGX_OK) {
                    return n;
                }
            }
        }
    }

    return NGX_PEER_INVALID;
}

static ngx_int_t
ngx_http_upstream_choose_by_rr(ngx_http_upstream_jvm_route_peer_data_t *jrp)
{
    ngx_uint_t                          i, n, all_busy = 0;
    ngx_uint_t                          npeers = jrp->peers->number;
    ngx_http_upstream_jvm_route_peer_t *peer;

    peer = jrp->peers->peer;
    while (1) {
        for (i = 0, n = jrp->current; i < npeers; i++, n = (n+1)%npeers) {

            if (peer[n].shared->current_weight <= 0) {
                continue;
            }

            if (ngx_http_upstream_jvm_route_try_peer(jrp, n) == NGX_OK) {
                return n;
            }
        }

        if (all_busy) {
            return NGX_PEER_INVALID;
        }

        for (i = 0; i < npeers; i++) {
            peer[i].shared->current_weight = peer[i].weight;
            all_busy = 1;
        }
    }

    return NGX_PEER_INVALID;
}

static ngx_int_t
ngx_http_upstream_jvm_route_choose_peer(ngx_peer_connection_t *pc, 
        ngx_http_upstream_jvm_route_peer_data_t *jrp)
{
    ngx_uint_t                          n;
    ngx_uint_t                          npeers = jrp->peers->number;
    ngx_http_upstream_jvm_route_peer_t *peer;

    if (npeers == 1) {
        n = 0;
        goto chosen;
    }

    if (jrp->cookie.len > 0) {
        n = ngx_http_upstream_choose_by_jvm_route(jrp);
        if (n != NGX_PEER_INVALID) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 
                    0, "[upstream_jvm_route] choose peer %i by jvm_route", n);
            goto chosen;
        }
    }

    n = ngx_http_upstream_choose_by_rr(jrp);
    if (n != NGX_PEER_INVALID) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 
                0, "[upstream_jvm_route] choose peer %i by rr", n);
        goto chosen;
    }

    return NGX_BUSY;

chosen:
    ngx_bitvector_set(jrp->tried, n);

    peer = &jrp->peers->peer[n];
    if (peer->shared->current_weight > 0) {
        peer->shared->current_weight--;
    }

    jrp->index = n;

    return NGX_OK;
}

static void
ngx_http_upstream_jvm_route_update_nreq(ngx_http_upstream_jvm_route_peer_data_t *jrp, 
        int delta, ngx_log_t *log)
{
    ngx_uint_t                          nreq;
    ngx_uint_t                          total_nreq;

    /* "kill -HUP" will generate a new peers */
    if (jrp->peers == jrp->peers->shared->peers && 
            jrp->peers->shared->generation == ngx_http_upstream_jvm_route_generation) {
        nreq = (jrp->peers->peer[jrp->current].shared->nreq += delta);
        total_nreq = (jrp->peers->shared->total_nreq += delta);

        ngx_log_debug6(NGX_LOG_DEBUG_HTTP, log, 0,
                "[upstream_jvm_route] nreq for peer %ui @ %p/%p now %d, total %d, delta %d",
                jrp->current, jrp->peers, jrp->peers->peer[jrp->current].shared, nreq,
                total_nreq, delta);
    }
}

static ngx_int_t
ngx_http_upstream_get_jvm_route_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                                ret;
    ngx_uint_t                               n = 0;
    ngx_atomic_t                            *lock;
    ngx_http_upstream_jvm_route_peer_t      *peer = NULL;
    ngx_http_upstream_jvm_route_peer_data_t *jrp = data;

    if (jrp->current == NGX_PEER_INVALID) {
        jrp->current = jrp->peers->current;
    }

    jrp->current = (jrp->current + 1) % jrp->peers->number;

    lock = &jrp->peers->shared->lock;
    ngx_spinlock(lock, ngx_pid, 1024);

    ret = ngx_http_upstream_jvm_route_choose_peer(pc, jrp);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
            "[upstream_jvm_route] jrp->current = %d, peer_id = %d, ret = %d", 
            jrp->current, jrp->index, ret);

    pc->tries--;

    if (ret == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                "[upstream_jvm_route] ALL the peers are busy now! "
                "Flush all the peers' failure countor to zero.");

        for (n = 0; n < jrp->peers->number; n++) {
            jrp->peers->peer[n].shared->fails = 0;
        }

        pc->name = jrp->peers->name;
        jrp->current = NGX_PEER_INVALID;
        ngx_spinlock_unlock(lock);
        return NGX_BUSY;
    }

    peer = &jrp->peers->peer[jrp->index];
    jrp->current = jrp->index;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    jrp->peers->current = jrp->current;

    /* "kill -HUP" will generate a new peers */
    if (jrp->peers != jrp->peers->shared->peers || 
            jrp->peers->shared->generation != ngx_http_upstream_jvm_route_generation) {
        ngx_spinlock_unlock(lock);
        return NGX_OK;
    }

    peer->shared->last_req_id = jrp->peers->shared->total_requests;
    ngx_http_upstream_jvm_route_update_nreq(jrp, 1, pc->log);
    peer->shared->total_req++;
    ngx_spinlock_unlock(lock);

    return NGX_OK;
}

static void
ngx_http_upstream_free_jvm_route_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_atomic_t                                *lock;
    ngx_http_upstream_jvm_route_peer_t          *peer;
    ngx_http_upstream_jvm_route_peer_data_t     *jrp = data;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, pc->log, 0, 
            "[upstream_jvm_route] jrp->current = %d, state = %ui, pc->tries = %d, pc->data = %p",
        jrp->current, state, pc->tries, pc->data);

    if (jrp->current == NGX_PEER_INVALID) {
        return;
    }

    peer = &jrp->peers->peer[jrp->current];
    lock = &jrp->peers->shared->lock;
    ngx_spinlock(lock, ngx_pid, 1024);

    /* "kill -HUP" will generate a new peers */
    if (jrp->peers != jrp->peers->shared->peers || 
            jrp->peers->shared->generation != ngx_http_upstream_jvm_route_generation) {
        ngx_spinlock_unlock(lock);
        return;
    }

    ngx_http_upstream_jvm_route_update_nreq(jrp, -1, pc->log);

    if (jrp->peers->number == 1) {
        pc->tries = 0;
    }

    if (state & NGX_PEER_FAILED) {
        peer->shared->fails++;
        peer->shared->total_fails++;
        peer->shared->accessed = ngx_time();

        if (peer->max_fails) {
            peer->shared->current_weight -= peer->weight / peer->max_fails;
        }

        if (peer->shared->current_weight < 0) {
            peer->shared->current_weight = 0;
        }
    }

    ngx_spinlock_unlock(lock);
}

#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_upstream_jvm_route_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                                rc;
    ngx_ssl_session_t                       *ssl_session;
    ngx_http_upstream_jvm_route_peer_t      *peer;
    ngx_http_upstream_jvm_route_peer_data_t *jrp = data;

    if (jrp->current == NGX_PEER_INVALID)
        return NGX_OK;

    peer = &jrp->peers->peer[jrp->current];

    /* TODO: threads only mutex */
    /* ngx_lock_mutex(jrp->peers->mutex); */

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "set session: %p:%d",
                   ssl_session, ssl_session ? ssl_session->references : 0);

    /* ngx_unlock_mutex(jrp->peers->mutex); */

    return rc;
}

static void
ngx_http_upstream_jvm_route_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_ssl_session_t                        *old_ssl_session, *ssl_session;
    ngx_http_upstream_jvm_route_peer_t       *peer;
    ngx_http_upstream_jvm_route_peer_data_t  *jrp = data;

    if (jrp->current == NGX_PEER_INVALID)
        return;

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "save session: %p:%d", ssl_session, ssl_session->references);

    peer = &jrp->peers->peer[jrp->current];

    /* TODO: threads only mutex */
    /* ngx_lock_mutex(jrp->peers->mutex); */

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    /* ngx_unlock_mutex(jrp->peers->mutex); */

    if (old_ssl_session) {

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "old session: %p:%d",
                       old_ssl_session, old_ssl_session->references);

        /* TODO: may block */

        ngx_ssl_free_session(old_ssl_session);
    }
}
#endif

static void *
ngx_http_upstream_jvm_route_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_jvm_route_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_jvm_route_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_upstream_jvm_route(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                              *value, *val_cookie;
    ngx_uint_t                              i, len;
    ngx_array_t                            *vars_lengths, *vars_values;
    ngx_http_script_compile_t               sc;
    ngx_http_upstream_srv_conf_t           *uscf;
    ngx_http_upstream_jvm_route_srv_conf_t *ujrscf;

    value = cf->args->elts;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    ujrscf = ngx_http_conf_upstream_srv_conf(uscf,
                                          ngx_http_upstream_jvm_route_module);

    if (value[1].len > 8 || ngx_strncmp(value[1].data, "$cookie_", 8) == 0 ) {
        for (i = 8; i < value[1].len; i++) {
            if (value[1].data[i] == '|') { 
                break;
            }
        }

        len = i;

        ujrscf->session_cookie.data = &value[1].data[8] ;
        ujrscf->session_cookie.len = len - 8;

        if (len == value[1].len) {
            val_cookie = &value[1];

            ujrscf->session_url.data = NULL;
            ujrscf->session_url.len = 0;
        }
        else {
            val_cookie = ngx_palloc(cf->pool, sizeof(ngx_str_t));
            if (val_cookie == NULL) {
                return NGX_CONF_ERROR;
            }
            val_cookie->data = &value[1].data[0]; 
            val_cookie->len = len; 

            len ++;
            ujrscf->session_url.data = &value[1].data[len];
            ujrscf->session_url.len = value[1].len - len;
        }
    }
    else {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    vars_lengths = NULL;
    vars_values = NULL;

    sc.cf = cf;
    sc.source = val_cookie;
    sc.lengths = &vars_lengths;
    sc.values = &vars_values;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts > 2) {
        if (ngx_strncmp(value[2].data, "reverse", 7) == 0 ) {
            ujrscf->reverse = 1;
        }
    }

    ujrscf->values = vars_values->elts;
    ujrscf->lengths = vars_lengths->elts;


    uscf->peer.init_upstream = ngx_http_upstream_init_jvm_route;

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE 
        | NGX_HTTP_UPSTREAM_MAX_FAILS
        | NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
        | NGX_HTTP_UPSTREAM_SRUN_ID
        | NGX_HTTP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}

extern volatile  ngx_cycle_t  *ngx_cycle;

static ngx_shm_zone_t *
ngx_shared_memory_find(ngx_str_t *name, void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = (ngx_list_part_t *) & (ngx_cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            continue;
        }

        return &shm_zone[i];
    }

    return NULL;
}

static ngx_int_t 
ngx_http_upstream_jvm_route_status_handler(ngx_http_request_t *r)
{
    u_char            *last;
    ngx_int_t          rc;
    ngx_uint_t         i;
    ngx_buf_t         *b;
    ngx_str_t          shm_name;
    ngx_chain_t        out;
    ngx_atomic_t      *lock;
    ngx_shm_zone_t    *shm_zone;
    ngx_http_upstream_jvm_route_shm_block_t *shm_block;
    ngx_http_upstream_jvm_route_peers_t     *peers;
    ngx_http_upstream_jvm_route_loc_conf_t  *ujrlcf;

    ujrlcf = ngx_http_get_module_loc_conf(r, ngx_http_upstream_jvm_route_module);

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    shm_name.data = ngx_palloc(r->pool, SHM_NAME_LEN);
    if (shm_name.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    last = ngx_snprintf(shm_name.data, SHM_NAME_LEN, "%V_%ui", 
	    &ujrlcf->shm_name, ngx_http_upstream_jvm_route_generation);
    shm_name.len = last - shm_name.data;

    shm_zone = ngx_shared_memory_find(&shm_name, &ngx_http_upstream_jvm_route_module);

    if (shm_zone == NULL || shm_zone->data == NULL) {

        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "can not find the shared memory zone \"%V\" ", &shm_name);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    shm_block = shm_zone->data;
    peers = shm_block->peers;

    b = ngx_create_temp_buf(r->pool, ngx_pagesize);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    lock = &peers->shared->lock;
    ngx_spinlock(lock, ngx_pid, 1024);

    if (peers) {
        b->last = ngx_sprintf(b->last, 
                "upstream %V: total_busy = %d, "
                "total_requests = %ui, " 
                "current_peer: %d/%d, " 
                "generation: %d\n\n", 
                peers->name, shm_block->total_nreq,
                shm_block->total_requests,
                peers->current + 1, peers->number,
                shm_block->generation);
        for (i = 0; i < peers->number; i++) {
            ngx_http_upstream_jvm_route_peer_t *peer = &peers->peer[i];
            ngx_http_upstream_jvm_route_shared_t *sh = peer->shared;
            b->last = ngx_sprintf(b->last, 
                    " peer %d: %V(%V) " 
                    "down: %d, fails: %d/%d, busy: %d/%d, " 
                    "weight: %d/%d, " 
                    "total_req: %ui, last_req: %ui, total_fails: %ui, fail_acc_time: %s",
                i + 1, &peer->name, &peer->srun_id, 
                peer->down, sh->fails, peer->max_fails, sh->nreq, peer->max_busy,
                sh->current_weight, peer->weight, 
                sh->total_req, sh->last_req_id, sh->total_fails, ctime(&sh->accessed));
        }
    }
    else {
        b->last = ngx_sprintf(b->last, 
                "upstream : total_busy = %ui, total_requests: %ui\n", 
                shm_block->total_nreq, shm_block->total_requests);
    }

    ngx_spinlock_unlock(lock);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static void * 
ngx_http_upstream_jvm_route_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_jvm_route_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_jvm_route_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    return conf;
}

static char *
ngx_http_upstream_jvm_route_set_status(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_jvm_route_loc_conf_t  *ujrlcf = conf;
    ngx_http_core_loc_conf_t                *clcf;
    ngx_str_t                               *value;

    value = cf->args->elts;

    ujrlcf->shm_name = value[1];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_jvm_route_status_handler;

    return NGX_CONF_OK;
}
