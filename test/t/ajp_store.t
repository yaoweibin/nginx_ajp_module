#
#===============================================================================
#
#         FILE:  sample.t
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 1 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the first time request for the cache
--- http_config
    upstream tomcats{      
        server 127.0.0.1:8009;
        keepalive 10;
    }

    ajp_cache_path /tmp/ajp_cache levels=1:2 keys_zone=ajp_cache_zone:10m inactive=24h max_size=1g;
--- config
    location / {
        root                 /tmp/ajp_store;
        error_page           404 = @fetch;
    }

    location @fetch {
        internal;
        ajp_pass           tomcats;
        ajp_store          on;
        ajp_store_access   user:rw  group:rw  all:r;

        root                 /tmp/ajp_store;
    }
--- request
    GET /index.html
--- error_code: 200
