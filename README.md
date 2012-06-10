node-spdy-proxy
===============

spdy/https proxy server based on node-spdy

It can be used as a standalone proxy server
or being embedded and/or extended in another
node.js application.

###Command Line Usage:

`runserver` will run the server with the
configurations specified in proxy.conf and fallback
to default settings if proxy.conf doesn't exist.

`node server.js [config_file]` will run the
server with the configurations specified in `confiig_file`
if it is given, otherwise act the same as `runserver`

###Configurations

`DEBUG`: debug mode, default to true

`log_file`: server log output, default to `proxy.log`

`ip_blacklist`: the IP blacklist file, with one IP each line terminated with \n

`host_blacklist`: the host blacklist file, same syntax with the IP blacklist

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
