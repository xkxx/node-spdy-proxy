/* Node SPDY Proxy
 * proxy server implementation
 * @author xkx
 * @copyright 2013
 * @licence GPL 3.0
 *
 * Credits:
 *
 * Ari Luotonen's paper Tunneling TCP based protocols through Web proxy servers
 * Peteris Krumins' 20 line HTTP Proxy, idea & ip blacklist
 * Joyent's nodejs & log code from util.js
*/

//imports
var http = require('http'),
	net = require('net'),
	spdy = require('spdy'),
	fs = require('fs'),
	common = require('./common.js'),
	parser = require('./parser.js');

// default config
var defaultConf = {
	DEBUG: true, //debug mode
	log_file: 'proxy.log', //log output
	ip_blacklist: null,
	host_blacklist: null,
	user_ca: null, // check user cert against this CA
	user_db: null, // json db for identify users
	security: {
		// enabled: true, // spdy operates on tls
		key: 'key.pem',
		cert: 'cert.pem'
	},
	declineHTTP: false, //decline HTTP connections?
	timeout: 10000, //Remote request timeout in milliseconds
	maxConnections: 100,
	noDelay: true,
	keepAlive: true,
	host: 'localhost', //server address
	ip: '127.0.0.1',
	port: 8080 //listening port
};

var Server = function(config, overrides) {

	var self = this;

	// Failure reading config is fatal. Errors thrown by readConf()
	// will cause the constructor to abort

	//try {
	this.config = config = common.readConf(config, defaultConf, overrides);
	//}

	var logger = new common.Logger(config);

	this.log = logger.log;
	this.debug = logger.debug;
	this.error = logger.error;

	// SPDY server requires SSL certificate. Errors thrown by enableSSL()
	// will cause the constructor to exit.
	var serverOptions = common.enableSSL(config);

	// optional user certificate varification

	if(config.user_ca) {
		try {
			var ca = fs.readFileSync(config.user_ca);

			serverOptions.ca = ca;
			serverOptions.requestCert = true;
			serverOptions.rejectUnauthorized = true;
		}
		catch (err) {
			this.error("Reading User CA failed: will not verify users");
			config.user_ca = null;
		}
	}

	// initiating
	spdy.server.Server.call(this, serverOptions);

	this.on("secureConnection", connectionHandler);

	this.on("request", requestHandler);
	this.on("connect", requestHandler);
	this.on("upgrade", requestHandler);
	this.on("checkContinue", requestHandler);

	this.on('clientError', function(e) {this.debug('----- client error -----');this.debug(e);});

	this.headDigester = parser.headDigester;
	this.createRequest = parser.createRequest;

	if (config.ip_blacklist) {
		common.watchListFile(this, config.ip_blacklist, 'ipBlackList');
		this._verifyClient = function (client) {
			if (self.ipBlackList.indexOf(client.IP) != -1) { //check if client is in blacklist
				self.log('Connection Declined (IP Ban): ' + client.remoteAddress);
				return false;
			}
			if (typeof self.verifyClient == 'function' && !self.verifyClient()) return false;
			return true;
		};
	}
	else {
		this._verifyClient = function() {
			if (typeof self.verifyClient == 'function' && !self.verifyClient()) return false;
			return true;
		};
	}

	if (config.host_blacklist) {
		common.watchListFile(this, config.host_blacklist, 'hostBlackList');
	}
	if (config.user_db) {
		common.watchUserDB(this, config.user_db);
	}

	this.maxConnections = config.maxConnections;
	this.maxHeadersCount = 60;

	this._listen = this.listen;
	this.listen = function(port) {
		this._listen(port? port : config.port);
		this.log('Server up listening at ' + config.host + ':' + config.port);
			process.on('uncaughtException', function(e) {
				self.log('[uncaughtException]: '+ e.message);
			});
	};
};
common.inherits(Server, spdy.server.Server);

exports.Server = Server;

var createServer = function(config, overrides) {
	return new Server(config, overrides);
};
exports.createServer = createServer;

var connectionHandler = function(client) {
	var debug, connection, IP, conID, user;
	debug = this.debug;
	connection = client.socket;
	IP = connection.IP = connection.remoteAddress;
	conID = connection.conID = IP + ':' + connection.remotePort;
	try {
		user = connection.user = this.userDB[connection.getPeerCertificate().fingerprint];
	}
	catch(err) {
		user = connection.user = 'anonymous';
	}
	debug('----- incoming connection! -----', conID);
	if (!this._verifyClient(client)) {
		client.destroy();
		return;
	}
	if (this.config.noDelay) client.setNoDelay(true);
	client.on('end', function() {
		debug('----- client end -----', conID);
	});
	client.on('close', function(e) {debug('----- client close ' + (e ? 'with' : 'without') + ' error -----', conID);});
	client.on('error', function(e) {debug('----- client error -----', conID);debug(e, conID);});
};

// client request handler
var requestHandler = function(request, response, head) {
	var log = this.log,
		debug = this.debug,
		config = this.config,
		createResponse = parser.httpCreateResponse,
		netCreateResponse = parser.netCreateResponse,
		isConnect = request.method == 'CONNECT',
		isUpgrade = request.headers.upgrade != null,
		IP, connection, user, conID;

	connection = request.isSpdy ? request.connection.socket.socket : request.connection.socket;

	IP = connection.IP;
	conID = connection.conID;
	user = connection.user;

	if(request.isSpdy) {
		conID += '#' + request.streamID;
	}

	var url = this.headDigester(request);

	if(url.illegalConnectURL) {
		log('Proxy Fetch Declined (illegalConnectURL): ' + IP);
		return createResponse('illegal-connect-url', response);
	}

	if (!url.host) { // unknown protocol
		// note that it also declines self-request without host header
		log('Proxy Fetch Declined (unknown): ' + IP); //record
		return createResponse('decline-unknown', response);
	}

	if ((url.host == config.host || url.host == config.ip) && url.port == config.port) { // they're coming for us!
		log('Server Visitor: ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);
		return createResponse(url.path, response);
	}

	if (isConnect && config.declineHTTP) { //decline http connection
		log('Proxy Fetch Declined (HTTP): ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);
		return createResponse('decline-http');
	}
	if (this.hostBlackList && this.hostBlackList.indexOf(url.host) != -1) { //check if host is in blacklist
		log('Proxy Fetch Declined (Host Ban): ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);
		return isConnect ? netCreateResponse('host-blacklisted', response) : createResponse('host-blacklisted');
	}

	if(this.verifyRequest && !this.verifyRequest(request, response, url)) return;

	log('Proxy Fetch: ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);

	if(isConnect) {
		debug('Connecting to remote socket: '+ url.host + ' ' + url.port);
		var remote = net.createConnection(url.port, url.host, function() {
			debug('----- remote server connected! -----', conID);
			if(head) remote.write(head);
			remote.setTimeout(0); // timeout only applies to new connections
			netCreateResponse('https-established', response);
			remote.pipe(response);
			response.pipe(remote);
		});
		if (config.noDelay) remote.setNoDelay(true);

		// error conditions
		remote.setTimeout(config.timeout, function() {
			debug('----- remote timeout -----', conID);
			remote.end();
			remote.destroy(); // ensure no more data will come in
			netCreateResponse('request-timeout', response);
		});
		response.on('error', function(e) {
			debug('----- client error -----', conID);debug(e, conID);
		});
		remote.on('error', function(e) {
			debug('----- remote error -----', conID); debug(e, conID);
			netCreateResponse(e.code, response);
		});
	}
	else { // default to http
		var reqObj = this.createRequest(request, url);
		debug("connecting to remote http server: " + url.host + ' ' + url.port);
		var remoteReq = http.request(reqObj, function(remoteRes) {
			debug('----- remote responded -----', conID);
			log('Fetch Received: ' + remoteRes.statusCode + ' by ' + remoteRes.headers.server);
			response.writeHead(remoteRes.statusCode, remoteRes.headers);
			remoteRes.pipe(response);
		});

		// normally, browsers send CONNECT for ws: and wss:
		// here we implement upgrade only for compatibility's sake
		remoteReq.on('upgrade', function(remoteRes, remoteSoc) {
			if (isUpgrade) {
				debug('----- remote sent upgrade -----', conID);
				log('Fetch Received: ' + remoteRes.statusCode + ' by ' + remoteRes.headers.server);
				netCreateResponse({
					statusCode: 101,
					reasonPhrase: 'Switching Protocols',
					headers: remoteRes.headers,
					noDefaultHeaders: true,
					nonFinal: true
				}, response);
				remoteSoc.pipe(response);
				response.pipe(remote);
			}
			else {
				debug('----- remote sent illegal upgrade -----', conID);
				remoteSoc.end();
				createResponse('illegal-response', response);
			}
			log('Fetch Received: ' + remoteRes.statusCode + ' by ' + remoteRes.headers.server);
			response.writeHead(remoteRes.statusCode, remoteRes.headers);
			remoteSoc.pipe(response);
		});
		remoteReq.on('continue', function(){
			response.writeContinue();
		});

		// set up client -> server pipe
		if (config.noDelay) remoteReq.setNoDelay(true);
		if (!isUpgrade) request.pipe(remoteReq);

		// error conditions
		remoteReq.on('connect', function(){
			debug('----- remote sent illegal connect -----', conID);
			remoteReq.abort();
			createResponse('illegal-response', response);
		});
		remoteReq.setTimeout(config.timeout, function() {
			debug('----- remote timeout -----', conID);
			remoteReq.abort();
			createResponse('request-timeout', response);
			response.end();
		});

		// debug info
		remoteReq.on('close', function() {
			debug('----- remote aborted -----', conID);
		});
		remoteReq.on('error', function(e) {
			debug('----- remote error -----', conID); debug(e, conID);
			createResponse(e.code, response);
		});
		response.on('close', function() {
			debug('----- client aborted -----', conID);
		});
	}
};

if(require.main === module) {
	createServer('proxy.conf').listen();
}