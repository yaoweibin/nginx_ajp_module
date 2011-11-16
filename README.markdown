

# Name



__nginx_ajp_module__ - support AJP protocol proxy with Nginx



# Synopsis





http {

    upstream tomcats {

        server 127.0.0.1:8009 srun_id=jvm1;

        jvm_route $cookie_JSESSIONID reverse;
        keepalive 10;
    }

    server {

        listen 80;

        location / {
            ajp_pass tomcats;
        }
    }
}





# Description

With this module, Nginx can connect to Tomcat's AJP port directly. The backend connections are keepalive, session sticky.
The motivation of writing these modules is Nginx's high performance and robustness.



# Directives





## ajp_buffers



__syntax:__ _ajp_buffers the_number is_size;_

__default:__ _ajp_buffers 8 4k/8k;_

__context:__ _http, server, location_

This directive sets the number and the size of buffers, into which will be read the response, obtained from the ajp server.  By default, the size of one buffer is equal to the size of pages. Depending on platform this is either 4K, 8K or 16K.



## ajp_buffer_size



__syntax:__ _ajp_buffer_size the_size;_

__default:__ _ajp_buffer_size 4k/8k;_

__context:__ _http, server, location_

This directive sets the buffersize, into which will be read the first part of the response, obtained from the ajp server.

In this part of response the small response-header is located, as a rule.

By default, the buffersize is equal to the size of one buffer in directive `ajp_buffers`; however, it is possible to set it to less.



## ajp_cache



__syntax:__ _ajp_cache zone;_

__default:__ _off_

__context:__ _http, server, location_

The directive specifies the area  which actually is the share memory's name for caching. The same area can be used in several places. You must set the `ajp_cache_path` first.



## ajp_cache_key



__syntax:__ _ajp_cache_key line;_

__default:__ _none_

__context:__ _http, server, location_

The directive specifies what information is included in the key for caching, for example



ajp_cache_key "$host$request_uri$cookie_user";



Note that by default, the hostname of the server is not included in the cache key. If you are using subdomains for different locations on your website, you need to include it, e.g. by changing the cache key to something like

ajp_cache_key "$scheme$host$request_uri";



## ajp_cache_methods



__syntax:__ _ajp_cache_methods [GET HEAD POST];_

__default:__ _ajp_cache_methods GET HEAD;_

__context:__ _main,http,location_

GET/HEAD is syntax sugar, i.e. you can not disable GET/HEAD even if you set just



ajp_cache_methods  POST;





## ajp_cache_min_uses



__syntax:__ _ajp_cache_min_uses n;_

__default:__ _ajp_cache_min_uses 1;_

__context:__ _http, server, location_

TODO: Description.



## ajp_cache_path



__syntax:__ _ajp_cache_path /path/to/cache [levels=m:n keys_zone=name:time inactive=time clean_time=time];_

__default:__ _none_

__context:__ _http, server, location_

This directive sets the cache path and other cache parameters. Cached data stored in files. Key and filename in cache is md5 of proxied URL. __Levels__ parameter set number of subdirectories in cache, for example for:



ajp_cache_path  /data/nginx/cache  levels=1:2   keys_zone=one:10m;



file names will be like:

/data/nginx/cache/c/29/b7f54b2df7773722d382f4809d65029c



## ajp_cache_use_stale



__syntax:__ _ajp_cache_use_stale [updating|error|timeout|invalid_header|http_500];_

__default:__ _ajp_cache_use_stale off;_

__context:__ _http, server, location_

TODO: Description.



## ajp_cache_valid



__syntax:__ _ajp_cache_valid [http_error_code|time];_

__default:__ _none_

__context:__ _http, server, location_

TODO: Description.



## ajp_connect_timeout



__syntax:__ _ajp_connect_timeout time;_

__default:__ _ajp_connect_timeout 60s;_

__context:__ _http, server, location_

This directive assigns a timeout for the connection to the upstream server. It is necessary to keep in mind that this time out cannot be more than 75 seconds.

This is not the time until the server returns the pages, this is the ["ajp_read_timeout"](#pod_"ajp_read_timeout")  statement. If your upstream server is up, but hanging (e.g. it does not have enough threads to process your request so it puts you in the pool of connections to deal with later), then this statement will not help as the connection to the server has been made.



## ajp_header_packet_buffer_size



__syntax:__ _ajp_header packet_buffer_size;_

__default:__ _ajp_header_packet_buffer_size 8k;_

__context:__ _http, server, location_

Set the buffer size of Forward Request packet. The range is (0, 2^16).



## ajp_hide_header



__syntax:__ _ajp_hide_header name;_

__context:__ _http, server, location_

By default, Nginx does not pass headers "Status" and "X-Accel-..." from the AJP process back to the client.  This directive can be used to hide other headers as well.

If the headers "Status" and "X-Accel-..." must be provided, then it is necessary to use directive ajp_pass_header to force them to be returned to the client.



## ajp_ignore_headers



__syntax:__ _ajp_ignore_headers name [name ...];_

__default:__ _none_

__context:__ _http, server, location_

This directive(0.7.54+) prohibits the processing of the header lines from the proxy server's response.

It can specify the string as "[X-Accel-Redirect](http://search.cpan.org/perldoc?NginxXSendfile)", "X-Accel-Expires", "Expires" or "Cache-Control".



## ajp_ignore_client_abort



__syntax:__ _ajp_ignore_client_abort on|off;_

__default:__ _ajp_ignore_client_abort off;_

__context:__ _http, server, location_

This directive determines if current request to the AJP-server must be aborted in case the client aborts the request to the server.



## ajp_intercept_errors



__syntax:__ _ajp_intercept_errors on|off;_

__default:__ _ajp_intercept_errors off;_

__context:__ _http, server, location_

This directive determines whether or not to transfer 4xx and 5xx errors back to the client or to allow Nginx to answer with directive error_page.

Note: You need to explicitly define the error_page handler for this for it to be useful. As Igor says, "nginx does not intercept an error if there is no custom handler for it it does not show its default pages. This allows to intercept some errors, while passing others as are."



## ajp_keep_conn



__syntax:__ _ajp_keep_conn on|off;_

__default:__ _ajp_keep_conn off;_

__context:__ _http, server, location_

This directive determines whether or not to keep the connectin alive with backend server.



## ajp_next_upstream



__syntax:__ _ajp_next_upstream [error|timeout|invalid_header|http_500|http_502|http_503|http_504|http_404|off];_

__default:__ _ajp_next_upstream error timeout;_

__context:__ _http, server, location_

Directive determines, in what cases the request will be transmitted to the next server:





- error — an error has occurred while connecting to the server, sending a request to it, or reading its response;

- timeout — occurred timeout during the connection with the server, transfer the request or while reading response from the server;

- invalid_header — server returned a empty or incorrect answer;

- http_500 — server returned answer with code 500;

- http_502 — server returned answer with code 502;

- http_503 — server returned answer with code 503;

- http_504 — server returned answer with code 504;

- http_404 — server returned answer with code 404;

- off — it forbids the request transfer to the next server Transferring the request to the next server is only possible when nothing has been transferred to the client -- that is, if an error or timeout arises in the middle of the transfer of the request, then it is not possible to retry the current request on a different server.





## ajp_max_data_packet_size



__syntax:__ _ajp_max_data_packet_size size;_

__default:__ _ajp_max_data_packet_size 8k;_

__context:__ _http, server, location_

Set the maximum size of AJP's Data packet. The range is [8k, 2^16];



## ajp_max_temp_file_size



__syntax:__ _ajp_max_temp_file_size size;_

__default:__ _ajp_max_temp_file_size 1G;_

__context:__ _http, server, location, if_

The maximum size of a temporary file when the content is larger than the proxy buffer.  If file is larger than this size, it will be served synchronously from upstream server rather than buffered to disk.

If ajp_max_temp_file_size is equal to zero, temporary files usage will be disabled.



## ajp_pass



__syntax:__ _ajp_pass ajp-server_

__default:__ _none_

__context:__ _location, if in location_

Directive assigns the port or socket on which the AJP-server is listening. Port can be indicated by itself or as an address and port, for example:



ajp_pass   localhost:9000;



using a Unix domain socket:



ajp_pass   unix:/tmp/ajp.socket;



You may also use an upstream block.



upstream backend  {

    server   localhost:1234;

}

ajp_pass   backend;



## ajp_pass_header



__syntax:__ _ajp_pass_header name;_

__context:__ _http, server, location_

TODO: Description.



## ajp_pass_request_headers



__syntax:__ _ajp_pass_request_headers [ on | off ];_

__default:__ _ajp_pass_request_headers on;_

__context:__ _http, server, location_

TODO: Description.



## ajp_pass_request_body



__syntax:__ _ajp_pass_request_body [ on | off ] ;_

__default:__ _ajp_pass_request_body on;_

__context:__ _http, server, location_

TODO: Description.



## ajp_read_timeout



__syntax:__ _ajp_read_timeout time;_

__default:__ _ajp_read_timeout_time 60_

__context:__ _http, server, location_

Directive sets the amount of time for upstream to wait for a ajp process to send data.  Change this directive if you have long running ajp processes that do not produce output until they have finished processing.  If you are seeing an upstream timed out error in the error log, then increase this parameter to something more appropriate.



## ajp_send_lowat



__syntax:__ _ajp_send_lowat [ on | off ];_

__default:__ _ajp_send_lowat off;_

__context:__ _http, server, location, if_

This directive set SO_SNDLOWAT. This directive is only available on FreeBSD



## ajp_send_timeout



__syntax:__ _ajp_send_timeout time;_

__default:__ _ajp_send_timeout 60;_

__context:__ _http, server, location_

This directive assigns timeout with the transfer of request to the upstream server. Timeout is established not on entire transfer of request, but only between two write operations. If after this time the upstream server will not take new data, then nginx is shutdown the connection.



## ajp_store



__syntax:__ _ajp_store [on | off | path] ;_

__default:__ _ajp_store off;_

__context:__ _http, server, location_

This directive sets the path in which upstream files are stored. The parameter "on" preserves files in accordance with path specified in directives _alias_ or _root_. The parameter "off" forbids storing. Furthermore, the name of the path can be clearly assigned with the aid of the line with the variables:

ajp_store   /data/www$original_uri;

The time of modification for the file will be set to the date of "Last-Modified" header in the response. To be able to safe files in this directory it is necessary that the path is under the directory with temporary files, given by directive ajp_temp_path for the data location.

This directive can be used for creating the local copies for dynamic output of the backend which is not very often changed, for example:

location /images/ {

    root                 /data/www;
    error_page           404 = @fetch;

}

location @fetch {

    internal;
    ajp_pass           backend;
    ajp_store          on;
    ajp_store_access   user:rw  group:rw  all:r;
    ajp_temp_path      /data/temp;

    root               /data/www;
}

To be clear ajp_store is not a cache, it's rather mirror on demand.



## ajp_store_access



__syntax:__ _ajp_store_access users:permissions [users:permission ...];_

__default:__ _ajp_store_access user:rw;_

__context:__ _http, server, location_

This directive assigns the permissions for the created files and directories, for example:

ajp_store_access  user:rw  group:rw  all:r;

If any rights for groups or all are assigned, then it is not necessary to assign rights for user:

ajp_store_access  group:rw  all:r;



## ajp_temp_path



__syntax:__ _ajp_temp_path dir-path [ level1 [ level2 [ level3 ] ] ] ;_

__default:__ _$NGX_PREFIX/ajp_temp_

__context:__ _http, server, location_

This directive works like L<NginxHttpCoreModule/"client_body_temp_path">  to specify a location to buffer large proxied requests to the filesystem.



## ajp_temp_file_write_size



__syntax:__ _ajp_temp_file_write_size size;_

__default:__ _ajp_temp_file_write_size ["#ajp buffer size"]  * 2;_

__context:__ _http, server, location, if_

Sets the amount of data that will be flushed to the ajp_temp_path when writing. It may be used to prevent a worker process blocking for too long while spooling data.



## jvm_route



__syntax:__ _jvm_route $cookie_SESSION_COOKIE[|session_url] [reverse]_

__default:__ _none_

__context:__ _upstream_

This directive comes from ngx_http_upstream_jvm_route_module ([http://code.google.com/p/nginx-upstream-jvm-route/](http://code.google.com/p/nginx-upstream-jvm-route/)).

'$cookie_SESSION_COOKIE' specifies the session cookie name(0.7.24+). 'session_url' specifies a different session name in the URL when the client does not accept a cookie. The session name is case-insensitive. In this module, if it does not find the session_url, it will use the session cookie name instead. So if the session name in cookie is the name with its in URL, you don't need give the session_url name.

With scanning this cookie, the module will send the request to right backend server. As far as I know, the resin's srun_id name is in the head of cookie. For example, requests with cookie value 'a$$$' are always sent to the server with the srun_id of 'a'. But tomcat's JSESSIONID is opposite, which is like '$$$.a'. The parameter of 'reverse' specifies the cookie scanned from tail to head.

If the request fails to be sent to the chosen backend server, It will try another server with the Round-Robin mode until all the upstream servers tried. The directive ajp_next_upstream can specify in what cases the request will be transmitted to the next server. If you want to force the session sticky, you can set 'ajp_next_upstream off'.



## jvm_route_status



__syntax:__ _jvm_route_status upstream_name_

__default:__ _none_

_'context:_ _location_

This directive comes from ngx_http_upstream_jvm_route_module ([http://code.google.com/p/nginx-upstream-jvm-route/](http://code.google.com/p/nginx-upstream-jvm-route/)).

Set the location of pages return the status of the jvm_route peers. Example:
location status {

    jvm_route_status backend;
}



## keepalive



__syntax:__ _keepalive <num> [single]_

__default:__ _none_

__context:__ _upstream_

Switches on keepalive module for the upstream in question. This directive comes from ngx_http_upstream_keepalive_module ([http://mdounin.ru/hg/ngx_http_upstream_keepalive/](http://mdounin.ru/hg/ngx_http_upstream_keepalive/)).

Parameters:



- num: Maximum number of connections to cache.  If there isn't enough room to cache new connections - last recently used connections will be kicked off the cache.

- single: Treat everything as single host.  With this flag connections to different backends are treated as equal.





## server(in upstream)



This directive comes from ngx_http_upstream_jvm_route_module ([http://code.google.com/p/nginx-upstream-jvm-route/](http://code.google.com/p/nginx-upstream-jvm-route/)).

Main syntax is the same as the official directive. This module add these parameters:



- 'srun_id': identifies the backend JVM's name by cookie. The default srun_id's value is 'a'. The name can be more than one letter.

- 'max_busy': the maximum of active connections with the backend server. The default value is 0 which means unlimited. If the server's active connections is higher than this parameter, it will not be chosen until the server is less busier. If all the servers are busy, Nginx will return 502.



NOTE: This module does not support the parameter of 'backup' yet.



# Installation



Download the latest version of the release tarball of this module from github ([http://github.com/yaoweibin/nginx_ajp_module](http://github.com/yaoweibin/nginx_ajp_module))

Grab the nginx source code from nginx.org ([http://nginx.org/](http://nginx.org/)), for example, the version 0.7.65 (see nginx compatibility), and then build the source with this module:

    $ wget 'http://nginx.org/download/nginx-0.7.65.tar.gz'
    $ tar -xzvf nginx-0.7.65.tar.gz
    $ cd nginx-0.7.65/
    $ patch -p1 < /path/to/nginx_ajp_module/ajp.patch

    $ ./configure --add-module=/path/to/nginx_ajp_module

    $ make
    $ make install



# Compatibility







- My test bed is 0.7.65 and 0.8.40.

- For Nginx-1.1.4+, you should use the branch for_1.1.4 ([https://github.com/yaoweibin/nginx_ajp_module/tree/for_1.1.4](https://github.com/yaoweibin/nginx_ajp_module/tree/for_1.1.4)).





# TODO







- SSL

- Backends connection pool?





# Known Issues







- Developing  





# Changelogs





## v0.1





- first release





# Authors







- Jinti Shen(路奇) _jinti.shen AT gmail DOT com_

- Joshua Zhu(叔度) _zhuzhaoyuan AT gmail DOT com_

- Simon Liu(雕梁) _simohayha.bobo AT gmail DOT com_

- Matthew Ma(东坡) _mj19821214 AT gmail DOT com_

- Weibin Yao(姚伟斌) _yaoweibin AT gmail DOT com_





# License



This README template is from agentzh ([http://github.com/agentzh](http://github.com/agentzh)).

I borrowed a lot of codes from Fastcgi module of Nginx. This part of code is copyrighted by Igor Sysoev. And the design of apache's mod_ajp_proxy ([http://httpd.apache.org/docs/trunk/mod/mod_proxy_ajp.html](http://httpd.apache.org/docs/trunk/mod/mod_proxy_ajp.html)). Thanks for their hard work.

This module is licensed under the BSD license.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:





- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.



THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.