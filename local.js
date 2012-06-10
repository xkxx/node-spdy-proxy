/* Node HTTPS Proxy
 * local side server test
 * @author xkx
 * @version 2.0.023
 * @copyright 2011
 * @licence GPL 3.0
 *
 * Credits:
 *
 * Ari Luotonen's paper Tunneling TCP based protocols through Web proxy servers
 * Peteris Krumins' 20 line HTTP Proxy, idea & ip blacklist
 * Joyent's nodejs & log code from util.js
*/

//settings
var settings = {
	DEBUG: true, //debug mode
	noDelay: true,
	timeout: 100000,
	port: 8088, //listening port
	secure: {
		enabled: true,
		key: 'key.pem',
		ca: ''
	},
	remote_host: '127.0.0.1',
	remote_port: 8086
};
//imports
var net = require('net'),
	tls = require('tls'),
	common = require('./common.js');
	parser = require('./parser.js');
//version
var version = '2.0.023';
var log = common.log;

//-------------here we go---------------------
log(common.about);

if (version !== common.version) {
	log("Program Exits: Component versions don't match");
	process.exit(1);
}
var socketOptions = {}; //Options for remote server connection
if(settings.secure.enabled) {
	socketOptions.key = common.getFileContent(settings.secure.key)[1];
}
if(settings.secure.ca) {
	socketOptions.ca = common.getFileContent(settings.secure.ca)[1];
}

//setup server
net.createServer(function(socket) {
	var client = socket, remote;
	if (settings.noDelay) client.setNoDelay(true);
	log('----------incoming connection!-----------');
	if (settings.secure.enabled) {
		remote = tls.connect(settings.remote_port, settings.remote_host, socketOptions);
	}
	else {
		remote = net.createConnection(settings.remote_port, settings.remote_host);
	}
	if (settings.timeout) remote.setTimeout(settings.timeout);
	if (settings.noDelay) remote.setNoDelay(true);

	remote.on('connect', function() {
		log('----------remote server connected!-----------');
		});
	remote.on('secureConnection', function() {
		log('----------SSL connection established!-----------');
	});
	remote.pipe(client);
	client.pipe(remote);
	remote.on('timeout', function() {
		log('----------remote-timeout-------');
		remote.end();
		client.end(parser.netCreateResponse('request-timeout'));
	});
	remote.on('close', function(e) {log('---------remote-close-' + (e ? 'with' : 'without') + '-flaw--------');
	});
	remote.on('error', function(e) {
		log('---------remote-error-------');log(e);
		if (e.errno === 61) client.end(parser.netCreateResponse('ECONNREFUSED'));
	});
	client.on('timeout', function() {log('----------proxy-timeout-------');});
	client.on('close', function(e) {log('--------proxy-close-' + (e ? 'with' : 'without') + '-flaw--------');});
	client.on('error', function(e) {log('---------proxy-error-------');log(e);});
	//end of new connection handler
}).listen(settings.port);

log('Server up listening at localhost:'+ settings.port);

process.on('uncaughtException', function(e) {
    log('-------uncaught-exception----------');
    log(e);
});