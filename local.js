/* Node HTTPS Proxy
 * local side server test
 * @author xkx
 * @version 2.0.024
 * @copyright 2013
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
		key: '',
		ca: ''
	},
	remote_host: '127.0.0.1',
	remote_port: 8080
};
//imports
var net = require('net'),
	tls = require('tls'),
	fs = require('fs'),
	common = require('./common.js'),
	parser = require('./parser.js');
//version
var version = '2.0.024';
var log = common.log;

// ----- here we go -----
log(common.about);

var socketOptions = {}; //Options for remote server connection
if(settings.secure.key) {
	socketOptions.key = fs.readFileSync(settings.secure.key);
}
if(settings.secure.ca) {
	socketOptions.ca = fs.readFileSync(settings.secure.ca);
}

// setup server
net.createServer(function(socket) {
	var client = socket, remote;
	if (settings.noDelay) client.setNoDelay(true);
	log('----------incoming connection!-----------');

	remote = tls.connect(settings.remote_port, settings.remote_host, socketOptions);

	if (settings.timeout) remote.setTimeout(settings.timeout);
	if (settings.noDelay) remote.setNoDelay(true);

	remote.on('secureConnection', function() {
		log('----------remote server connected!-----------');
		});
	remote.pipe(client);
	client.pipe(remote);
	remote.on('timeout', function() {
		log('----------remote-timeout-------');
		remote.end();
		client.end(parser.netCreateResponse('request-timeout'));
	});
	remote.on('close', function(e) {log('---------remote-close-----');
	});
	remote.on('error', function(e) {
		log('---------remote-error-------');log(e);
		if (e.errno === 61) client.end(parser.netCreateResponse('ECONNREFUSED'));
	});
	client.on('timeout', function() {log('----------proxy-timeout-------');});
	client.on('close', function(e) {log('--------proxy-close-----');});
	client.on('error', function(e) {log('---------proxy-error-------');log(e);});
	//end of new connection handler
}).listen(settings.port);

log('Server up listening at localhost:'+ settings.port);

process.on('uncaughtException', function(e) {
    log('-------uncaught-exception----------');
    log(e);
});