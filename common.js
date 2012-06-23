/* Node HTTPS Proxy
 * common stuff
 * @author xkx
 * @version 2.0.024
 * @copyright 2011
 * @licence GPL 3.0
 *
 * Credits:
 *
 * Ari Luotonen's paper Tunneling TCP based protocols through Web proxy servers
 * Peteris Krumins' 20 line HTTP Proxy, idea & ip blacklist
 * Joyent's nodejs & log code from util.js
*/
//version
var version = exports.version = '2.0.024';

exports.about = '/* Node HTTPS Proxy\n' +
		' * @author xkx\n' +
		' * @version ' + version + '\n' +
		' * @copyright 2012\n' +
		' * @licence GPL 3.0\n' +
		' * \n' +
		' * Credits:\n' +
		' * \n' +
		" * Ari Luotonen's paper Tunneling TCP based protocols through Web proxy servers\n" +
		" * Peteris Krumins' 20 line HTTP Proxy, idea & ip blacklist\n" +
		" * Joyent's node.js & logging code from util.js\n" +
		'*/';

var util = require('util'),
	fs = require('fs');

var default_config_address = 'proxy.conf';

var log = exports.log = util.log;

exports.inherits = util.inherits;

//copy from util.js
var joyent_util = {
	pad: function(n) {
		return n < 10 ? '0' + n.toString(10) : n.toString(10);
	},
	months: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'],
	// 26 Feb 16:19:34
	timestamp: function() {
		var d = new Date();
		var time = [this.pad(d.getHours()),
					this.pad(d.getMinutes()),
					this.pad(d.getSeconds())].join(':');
		return [d.getDate(), this.months[d.getMonth()], time].join(' ');
	}
};

exports.Logger = function(settings) {
	var log;
	if (settings.log_file) {
		var logFile = fs.createWriteStream(settings.log_file, {flags: 'a'});
		log = this.log = function(stg) //server log
		{
			logFile.write(joyent_util.timestamp() + ' - ' + stg.toString() + '\n');
			util.log(stg);
		};
	}
	else {
		log = this.log = util.log;
	}
	process.on('exit', function() {
		log('Server is about to exit');
		logFile.end();
	});
	process.on('uncaughtException', function(e) {
		if (errorAcceptable(e)) return;
		log('!!!ERROR!!!');
		log(e);
	});
	this.debug = function(stg, conID) {
		if (settings.DEBUG) {
		conID = conID ? conID + ' -' : '';
		util.log(conID + stg);
		}
	};
	return true;
};

var getFileContent = function(filename) {
	var content = null, error = null;
	try {
		content = fs.readFileSync(filename, 'utf-8');
	}
	catch (err) {
		error = err.errno == 9 ? 'fileNotFound' : err.message;
	}
	return [error, content];
};
exports.getFileContent = getFileContent;

exports.enableSSL = function(key, cert, logger) {
	var result = {};
	var log = logger.log, debug = logger.debug;
	log("Reading SSL key and cert files...");
	var key_file = getFileContent(key);
	if (key_file[0]) {
		debug('Failed to read server key: ' + key_file[0]);
		return null;
	}
	result.key = key_file[1];
	var cert_file = getFileContent(cert);
	if (cert_file[0]) {
		debug('Failed to read server cert: ' + cert_file[0]);
		return null;
	}
	result.cert = cert_file[1];

	// to counter BEAST attacks
	result.ciphers = "ECDHE-RSA-AES256-SHA:AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM";
	result.honorCipherOrder = true;

	log('SSL enabled successfully');
	return result;
};
exports.readConf = function(settings, defaultSettings) {
	var msg;
	if (typeof settings ==  'string') {
		var f = getFileContent(settings);
		if (f[0]) {
			if (f[0] == 'fileNotFound') { //file doesn't exist
				fs.writeFile(default_config_address, JSON.stringify(defaultSettings));
				msg = "Config file doesn't exist. Created one at " + default_config_address;
			}
			else {
				msg = "Reading config failed: " + f[0];
			}
			settings = {};
		}
		else {
			try {
				settings = JSON.parse(f[1]);
			}
			catch (e) {
				msg = 'Loading config failed: ' + e.type;
				settings = {};
			}
		}
	}
	else if(!settings) {
		msg = "Config not provided. Use default settings";
		settings = {};
	}
	for (var i in defaultSettings) {
		if (typeof settings[i] == 'undefined')
			settings[i] = defaultSettings[i];
	}
	if (!msg) msg = 'Read config successfully';
	return [msg, settings];
};

//utils for the server
exports.watchListFile = function(server, filename, listname) {
	var log = server.log, debug = server.debug;
	var readList = function() {
		debug('-------updating ' + listname +'-------');
		var f = getFileContent(filename);
		if (f[0]) { // error
			debug('Failed to read ' + listname + ': ' + f.error);
			return;
		}
		server[listname] = f[1].toString().split('\n').filter(function(item) { return item.length; });
		debug(server[listname]);
		log(listname +' updated');
	};
	fs.watch(filename, readList);
	log('Watching ' + listname +' at: ' + filename);
	readList();
};

exports.watchUserDB = function(server, filename) {
	var log = server.log, debug = server.debug;
	var readList = function() {
		debug('-------updating userDB-------');
		var f = getFileContent(filename);
		if (f[0]) { // error
			debug('Failed to read userDB: ' + f.error);
			return;
		}
		server.userdb = JSON.parse(f[1]);
		debug(server.userdb);
		log('userDB updated');
	};
	fs.watch(filename, readList);
	log('Watching userDB at: ' + filename);
	readList();
};

//runtime error handling
var errorAcceptable = function(e) {
	return false;
};
