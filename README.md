node-spdy-proxy
===============

**node-spdy-proxy** is a spdy/https proxy server utility based on node-spdy.

### Features

* Works standalone or as a part of other applications
* SPDY v2/3 capable, with graceful degredation to normal HTTPS
* Full-feature support for HTTP/HTTPS, correctly handles websocket upgrades
* Client authentication by certificates
* Host/IP blacklist support
* Client management based on pubkey fingerprints
* Extensive logging and debugging information

### Why SPDY?

SPDY is the next generation HTTP/S. Over a high-latency channel,
SPDY can effectively reduce roundtrips and improve 
network responsiveness. It adds header compression, stream multiplexing and flow control to HTTP/S. These features enables SPDY to become a great candidate for network-optimizing proxies.

###What is the Purpose of node-spdy-proxy?

node-spdy-proxy is a network-optimizing proxy, similar to the ones deployed on Amazon Silk and the latest version of Google Chrome for Android. It improves network responsiveness over high-latency channels (such as satellite or wireless connections) by acting as the gateway between the client behind these channels and the datacenter. 

### Usage

`runserver` starts the proxy server with the
configurations specified in proxy.conf with fallback
to default settings if proxy.conf doesn't exist.

#### Command-line Usage

```  Usage: runserver [config_file]

  Options:

    -h, --help                 output usage information
    -o, --overrides [options]  specify extra options, overrides the config file
    -p, --port [port_number]   Bind server to the specified port, overrides other configurations
    -V, --credits              Print software version and credits
```

### Configurations

Configurations are specified in `proxy.conf`. Detailed explanation for each option is as follows,

* `DEBUG`: whether to enable debug mode, defaults to `true`

* `log_file`: server log output, defaults to `proxy.log`

* `ip_blacklist`: the path to the IP blacklist file. The file must be a plain-text file with one IP address on each line terminated with `\n`. If set to `null`, this features is disabled. Defaults to `null`

* `host_blacklist`: the path to the host blacklist file. The file must be a plain-text file with one host name on each line terminated with `\n`. If set to `null`, this features is disabled. Defaults to `null`

* `user_ca`: the path to the certificate of a certificate authority. When enabled, each client must provide a certificate signed by this CA. Unauthenticated clients are disconnected. If set to `null`, this features is disabled. Defaults to `null`

* `user_db`: the path to a JSON file that identifies each user by the fingerprint of their certificate. The username will then appear in the log file each time a proxy request is sent. If set to `null`, every user will bear the name `anonymous`. Defaults to `null`

* `security: {`

`key`: path to the TLS key file, defaults to `key.pem`

`cert`: path to the TLS certificate file, defaults to `cert.pem`

`},`

* `declineHTTP`: if set to true, the server will decline HTTP connections. Defaults to `false`

* `timeout`: Remote server timeout in milliseconds, the default is 10000ms. Note that it only applies to new connections.

* `maxConnections`: Maximum number of connections, defaults to 100

* `noDelay`: Whether connections should not be buffered, defaults to true

* `keepAlive`: Whether to allow HTTP connections to keep-alive, defaults to true

* `host`: hostname of the proxy server, defaults to `localhost`

* `ip`: IP address of the proxy server, defaults to `127.0.0.1`

* `port`: listening port, defaults to 8080.
