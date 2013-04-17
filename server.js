/* Node SPDY Proxy
 * proxy server implementation
 * @author xkx
 * @copyright 2011
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

//settings
var defaultSettings = {
	DEBUG: true, //debug mode
	log_file: 'proxy.log', //log output
	ip_blacklist: null,
	host_blacklist: null,
	user_ca: null, // check user cert against this CA
	user_db: null, // json db for identify users
	secure: {
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
	// will cause the constructor to abort, leaving the bloody mess to
	// the caller to deal with

	//try {
	this.config = config = common.readConf(config, defaultSettings, overrides);
	//}

	var logger = new common.Logger(config);

	this.log = logger.log;
	this.debug = logger.debug;
	this.error = logger.error;

	// SPDY proxy requires SSL certificate. Errors thrown by enableSSL
	// will cause the constructor to exit.
	var serverOptions = common.enableSSL(config);

	// optional user certificate varification 

	if(config.user_ca) {
		var ca;
		try {
			ca = fs.readFileSync(config.user_ca);

			serverOptions.ca = ca;
			serverOptions.requestCert = true;
			serverOptions.rejectUnauthorized = true;
		}
		catch (err) {
			this.error("Reading User CA failed: will not verify users");
			config.user_ca = null;
		}
	}

	//initiating
	spdy.server.Server.call(this, serverOptions);

	this.on("connection", connectionHandler);
	this.on("request", requestHandler);
	this.on("checkContinue", requestHandler);
	this.on("connect", requestHandler);

	this.on('clientError', function(e) {this.debug('------client-error-----');this.debug(e + e.code);});

	this.headDigester = parser.headDigester;
	this.createRequest = parser.createRequest;

	if (config.ip_blacklist) {
		common.watchListFile(this, config.ip_blacklist, 'ipBlackList');
		this._verifyClient = function (client) {
			if (self.ipBlackList.indexOf(client.IP) != -1) { //check if client is in blacklist
				self.log('Connection Declined: (IP Ban) ' + client.remoteAddress); //record
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

	if (config.host_blacklist)
		common.watchListFile(this, config.host_blacklist, 'hostBlackList');
	if (config.user_db)
		common.watchUserDB(this, config.user_db);

	this.maxConnections = config.maxConnections;
	this.maxHeadersCount = 60;

	this._listen = this.listen;
	this.listen = function(port) {
		this._listen(port? port : config.port);
		this.log('Server up listening at ' + config.host + ':' + config.port);
			process.on('uncaughtException', function(e) {
				this.log('[uncaughtException]: '+ e.message);
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
	var debug = this.debug;
	var IP = client.remoteAddress || client.socket.remoteAddress;
	var conID = IP + ':' + client.remotePort;
	debug('------incoming connection!------', conID);
	if (!this._verifyClient(client)) {
		client.destroy();
		return;
	}
	if (this.settings.noDelay) client.setNoDelay(true);
	client.on('end', function() {
		debug('------client-end------', conID);
	});
	client.on('close', function(e) {debug('------client-close-' + (e ? 'with' : 'without') + '-error------', conID);});
	client.on('error', function(e) {debug('------client-error------', conID);debug(e + e.code, conID);});
};

// client request handler
var requestHandler = function(request, response, head) {
	var log = this.log, debug = this.debug, settings = this.settings, createResponse = parser.httpCreateResponse.bind(response),
		IP, connection, user, conID;

	if(request.isSpdy)
		connection = request.connection.connection.socket;
	else
		connection = request.connection.socket;

	IP = request.IP = connection.remoteAddress;
	conID = IP + ':' + connection.remotePort;

	if(request.isSpdy) conID += '#' + request.streamID;

	try {
		user = this.userDB[connection.getPeerCertificate().fingerprint];
	}
	catch(e) {
		user = 'unknown';
	}

	var url = this.headDigester(request);

	if(url.illegalConnectURL) {
		log('Proxy Fetch Declined: (illegalConnectURL) ' + IP); //record
		createResponse('illegal-connect-url', response);
		return;
	}

	if (!url.host) { //unknown protocol
		log('Proxy Fetch Declined: (unknown) ' + IP); //record
		createResponse('decline-unknown', response);
		response.end();
		return;
	}

	if ((url.host == settings.host || url.host == settings.ip) && url.port == settings.port) { //they're coming for us!
		log('Server Visitor: ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);
		createResponse(url.path, response);
		response.end();
		return;
	}

	if (request.method != 'CONNECT' && this.settings.declineHTTP) { //decline http connection
			createResponse('decline-http');
			log('Proxy Fetch Declined: (HTTP) ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);
			return false;
		}
	if (this.hostBlackList && this.hostBlackList.indexOf(url.host) != -1) { //check if host is in blacklist
			log('Proxy Fetch Declined: (Host Ban) ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);
			if(request.method != 'CONNECT')
				createResponse('host-blacklisted');
			else
				parser.netCreateResponse('host-blacklisted');

			return false;
	}

	if(this.verifyRequest && !this.verifyRequest(request, response, url)) return;
	
	log('Proxy Fetch: ' + request.method + ' ' + request.url + ' from ' + user + '@' + IP + ' with ' + request.headers['user-agent']);

	if(request.method == "CONNECT") { //connect request
		debug('Connecting to remote socket: '+ url.host + ' ' + url.port);
		var remote = net.createConnection(url.port, url.host, function() {
			debug('------remote server connected!------', conID);
			if(head) remote.write(head);
			if(response.writable) response.write(parser.netCreateResponse('https-established'));
			remote.pipe(response);
			response.pipe(remote);
		});
		if (settings.noDelay) remote.setNoDelay(true);
		remote.setTimeout(settings.timeout, function() {
			debug('------remote-timeout------', conID);
			remote.end(); // FIXME: should we destroy?
		});
		response.on('error', function(e) {
			debug('------client-error------', conID);debug(e + e.code, conID);
		});
		remote.on('error', function(e) {
			debug('------remote-error------', conID);debug(e + e.code, conID);
			//FIXME: make sure it's closed?
		});
	}
	else { //default to http
		var reqObj = this.createRequest(request, url);
		debug("connecting to remote http server: " + url.host + ' ' + url.port);
		var remoteReq = http.request(reqObj, function(remoteRes) {
			debug('------remote-responded------', conID);
			log('Fetch Received: ' + remoteRes.statusCode + ' by ' + remoteRes.headers.server);
			response.writeHead(remoteRes.statusCode, remoteRes.headers);
			remoteRes.pipe(response);
		});
		remoteReq.on('continue', function(){
			response.writeContinue();
		});
		remoteReq.on('connect', function(){
			debug('-----remote-sent-connect-----');
			remoteReq.abort();
			createResponse('illegal-response', response);
		});
		remoteReq.on('upgrade', function(){
			debug('-----remote-sent-upgrade-----');
			remoteReq.abort();
			createResponse('illegal-response', response);
		});
		if (settings.noDelay) remoteReq.setNoDelay(true);
		remoteReq.setTimeout(settings.timeout, function(){
			debug('------remote-timeout------', conID);
			remoteReq.abort();
			createResponse('request-timeout', response);
			response.end();
		});
		request.pipe(remoteReq);

		remoteReq.on('close', function(){
			debug('------remote-aborted------', conID);
		});
		remoteReq.on('error', function(e){
			debug('------remote-error------', conID); debug(e + e.code, conID);
			createResponse(e.code, response);
		});
		response.on('close', function(){
			debug('------client-aborted------', conID);
		});
	}
};