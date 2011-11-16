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

plan tests => repeat_each() * 2 * blocks();
$ENV{TEST_NGINX_TOMCAT_AJP_PORT} ||= 8009;
no_root_location();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the GET of AJP with keepalive
--- http_config
    upstream tomcats{      
        server 127.0.0.1:$TEST_NGINX_TOMCAT_AJP_PORT;
        keepalive 10;
    }
--- config
    location / {
        ajp_keep_conn on;
        ajp_pass tomcats;
    }
--- request
    GET /index.html
--- response_body_like: ^(.*)$

=== TEST 2: the GET of AJP without keepalive
--- http_config
    upstream tomcats{      
        server 127.0.0.1:$TEST_NGINX_TOMCAT_AJP_PORT;
    }
--- config
    location / {      
        ajp_pass tomcats;
    }
--- request
    GET /index.html
--- response_body_like: ^(.*)$

=== TEST 3: the GET of AJP without keepalive module
--- http_config
    upstream tomcats{
        server 127.0.0.1:8009;
    }
--- config
    location / {      
        ajp_keep_conn on;
        ajp_pass tomcats;
    }
--- request
    GET /index.html
--- response_body_like: ^(.*)$
