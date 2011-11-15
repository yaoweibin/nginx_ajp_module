#!/bin/sh

#for slow network, need test with etcproxy
#TEST_NGINX_TOMCAT_AJP_PORT=1234 PATH=/home/yaoweibin/nginx/sbin:$PATH prove -r t

#for general test
PATH=/home/yaoweibin/nginx/sbin:$PATH prove -r t
