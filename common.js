/* Node HTTPS Proxy
 * common stuff
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

//version
var version = exports.version = '2.0.025';

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

exports.inherits = util.inherits;

/* ===================
 *  Simple Logger
 */

var log = exports.log = util.log;

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
	var log, DEBUG = settings.DEBUG;
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
	this.error = function(string) {
		log('[ERROR]:' + string);
	};
	this.debug = function(string, conID) {
		if (DEBUG) {
			conID = conID ? conID + ' -' : '';
			log(conID + string);
		}
	};
	return true;
};

/* ===================
 *  Configuration parsers
 */

exports.enableSSL = function(config) {
	var result = {};
    try {
        result.key = fs.readFileSync(config.security.key);
    }
    catch(err) {
		throw 'Failed to read server key: ' + err;
	}
    try {
        result.cert = fs.readFileSync(config.security.cert);
    }
	catch(err) {
		throw 'Failed to read server cert: ' + err;
	}

	// to counter BEAST attacks
	result.honorCipherOrder = true;
	return result;
};
exports.readConf = function(config, defaultSettings, overrides) {
	// try reading from file
	if (typeof config ==  'string') {
		try {
			var file = fs.readFileSync(config, 'utf-8');
			config = JSON.parse(file);
		}
		catch(err) {
			throw "Reading config failed: " + err.message;
		}
	}
	else if (typeof config != 'object') {
		throw "Invalid argument config: must be a string or object";
	}
	for (var i in defaultSettings) {
		if (typeof config[i] == 'undefined')
			config[i] = defaultSettings[i];
	}
	if(typeof overrides == 'object') {

		for (i in overrides) {
			if (typeof config[i] != 'undefined')
				config[i] = overrides[i];
		}
	}
	return config;
};

exports.watchListFile = function(server, filename, listname) {
	var readList = function() {
		server.debug('-------updating ' + listname +'-------');
		try {
			var file = fs.readFileSync(filename, 'utf-8');
			server[listname] = file.split('\n').filter(function(item) { return item.length; });
			server.debug(server[listname]);
			server.log(listname +' updated');
		}
		catch(err) {
			server.error('Failed to read ' + listname + ': ' + err.message);
			return;
		}
	};
	fs.watch(filename, readList);
	server.log('Watching ' + listname +' at: ' + filename);
	readList();
};

exports.watchUserDB = function(server, filename) {
	var readList = function() {
		server.debug('-------updating userDB-------');
		try {
			var file = fs.readFileSync(filename, 'utf-8');
			server.userdb = JSON.parse(file);
			server.debug(server.userdb);
			server.log('userDB updated');
		}
		catch(err) {
			server.debug('Failed to read userDB: ' + err.message);
			return;
		}
	};
	fs.watch(filename, readList);
	server.log('Watching userDB at: ' + filename);
	readList();
};

//runtime error handling
var errorAcceptable = function(e) {
	return false;
};
