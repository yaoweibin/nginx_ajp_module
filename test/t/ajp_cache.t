# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();
$ENV{TEST_NGINX_TOMCAT_AJP_PORT} ||= 8009;
no_root_location();
no_shuffle();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the first time request for the cache
--- http_config
    upstream tomcats{
        server 127.0.0.1:$TEST_NGINX_TOMCAT_AJP_PORT;
        keepalive 10;
    }

    ajp_cache_path /tmp/ajp_cache levels=1:2 keys_zone=ajp_cache_zone:10m inactive=24h max_size=1g;
--- config
    location / {
        ajp_cache "ajp_cache_zone";
        ajp_cache_key "$host$request_uri$cookie_user";
        ajp_cache_valid 200 1d;
        ajp_cache_use_stale error timeout invalid_header updating http_500;
        add_header X-Cache $upstream_cache_status;

        ajp_pass tomcats;
    }
--- request
    GET /index.html
--- response_headers
    X-Cache: MISS

=== TEST 2: the second time request for the cache
--- http_config
    upstream tomcats{
        server 127.0.0.1:$TEST_NGINX_TOMCAT_AJP_PORT;
        keepalive 10;
    }

    ajp_cache_path /tmp/ajp_cache levels=1:2 keys_zone=ajp_cache_zone:10m inactive=24h max_size=1g;
--- config
    location / {
        ajp_cache "ajp_cache_zone";
        ajp_cache_key "$host$request_uri$cookie_user";
        ajp_cache_valid 200 1d;
        ajp_cache_use_stale error timeout invalid_header updating http_500;
        add_header X-Cache $upstream_cache_status;

        ajp_pass tomcats;
    }
--- request
    GET /index.html
--- response_headers
    X-Cache: HIT
