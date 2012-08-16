node-spdy-proxy
===============

spdy/https proxy server based on node-spdy

It can be used as a standalone proxy server
or being embedded and/or extended in another
node.js application.

###Why SPDY?

SPDY improves connection latency and throughput by
compacting multiple streams in one tls connection and
enabling gzip compression by default. According to Google,
SPDY promises 27% to 60% speedup over HTTP and 39 - 55%
over HTTPS [1].

[1]: http://www.chromium.org/spdy/spdy-whitepaper/

###What is the Purpose of node-spdy-proxy?

By deploying a SPDY proxy between the client and the 
non-SPDY-enabled Internet, it can potentially improve the
Internet latency from the client's perspective. Especially
when the connection between the browser and the actual
website is slow, the full TCP roundtrips saved by SPDY
can dramatically reduce the site loading times, the rationale
behind Amazon Silk [2].

A lightweight SPDY proxy written in Node.js offers the benefit
of SPDY without the hassle of setting up a full-blown proxy
server, and thus comes node-spdy-proxy.
[2]: http://en.wikipedia.org/wiki/Amazon_Silk

###Command Line Usage

`runserver` will start the server with the
configurations specified in proxy.conf and fallback
to default settings if proxy.conf doesn't exist.

`node server.js [config_file]` will run the
server with the configurations specified in `config_file`
if it is given, otherwise act the same as `runserver`

###Configurations

`DEBUG`: debug mode, default to true

`log_file`: server log output, default to `proxy.log`

`ip_blacklist`: the IP blacklist file, with one IP address
each line terminated with \n

`host_blacklist`: the host blacklist file, same syntax as the IP blacklist

`user_ca`: will check user certificate against this CA if given

`user_db`: a json file that identifies users against the fingerprints of their certificates

`secure: {`

`key`: tls key file, default to `key.pem`

`cert`: tls certificate file, default to `cert.pem`

`},`

`declineHTTP`: if set to true, will decline HTTP connections. Default to `false`

`timeout`: Remote server timeout in milliseconds, the default is 10000ms

`maxConnections`: Maximum number of connections, default to 100

`noDelay`: Set nodelay for client and remote sockets, default to true

`keepAlive`: Allow HTTP connections to keep-alive

`host`: proxy server hostname, default to `localhost`

`ip`: proxy server IP address, default to `127.0.0.1`

`port`: listening port, default to 8080.
