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


var common = require('./common.js'),
	util   = require('util'),
	url    = require('url');

//regExps
var regexps = {
	hostname    : /([\w\d\._-]+):([\d]+)/,
	fullPath    : /[\w]+:\/\/[\S]+/,
	shortPath   : /\/[\S]*/,
	httpVersion : /HTTP\/\d.\d/,
	port        : /:[\d]+/,
	parse       : function(regexp, string) {
		var match = string.match(regexps[regexp]);
			return (match) ? null : match.toString();
	}
};

// header digester
// the url can be one of the following:
// server:port
// scheme://server:port/path
// /path

exports.headDigester = function(request) {
	var index, urlObj, path = request.url;
	if (request.method == "CONNECT") {
		var match = path.match(regexps.hostname);

		if(match) {
			return {host: match[1], port: match[2]};
		}
		else {
			return {illegalConnectURL: true};
		}
	}
	var host = request.headers.host;
	if (host) { //optimization
		index = host.indexOf(':');
		if(index == -1)
			urlObj = {host: host, port: 80};
		else
			urlObj = {host: host.slice(0, index), port: host.slice(index+1)};

		//stripe off scheme
		index = request.url.indexOf('//');
		if(index != -1) {
			path = request.url.slice(index+2);
		}
		//stripe off hostname
		index = path.indexOf('/');
		if(index != -1) {
			urlObj.path = path.slice(index);
		}
		return urlObj;
	}
	urlObj = url.parse(request.url); //TODO: optimize by writing reg maybe?
	url.port = url.port || 80;
	return urlObj;
};

//adapt head string for remote server
exports.createRequest = function(request, url) {
	var requestObj = url;
	requestObj.headers = request.headers;
	requestObj.method = request.method;
	var connection = requestObj.headers['proxy-connection'];
	if(connection) {
		delete requestObj.headers['proxy-connection'];
		requestObj.headers.connection = connection;
	}
	delete requestObj.headers['proxy-authorization'];
	return requestObj;
};

var httpHead = 'HTTP/1.1 ', CRLF = '\r\n', br = '<br/>';
//create http response
exports.httpCreateResponse = function(type, response) {
	var content, headers;

	if (typeof type === 'string') {
		content = responses[type] || responses['default'];
	}
	else {
	  	content = type;
	}
	headers = content.headers || {};

	if (!content.noDefaultHeaders) {
		headers.server = headers.server || 'Server: Nginx/1.1.0';
		if (content.html) {
			headers['content-length'] = content.html.length;
			headers['content-type'] = 'text/html';
		}
	}
	response.writeHead(content.statusCode, content.reasonPhrase, headers);
	if(content.html) response.write(content.html);
	response.end();
};

exports.netCreateResponse = function(type) {
	var content, headers;

	if (typeof type === 'string') {
		content = responses[type] || responses['default'];
	}
	else {
	  	content = type;
	}
	headers = content.headers || {};

	var result = httpHead + content.statusCode + ' ' + content.reasonPhrase + CRLF;
	if (!content.noDefaultHeaders) {
		result += 'Date: ' + new Date().toUTCString() + CRLF;
		if (!headers.Server) result += 'Server: Nginx/1.1.0' + CRLF;
		if (content.html) {
			result += 'Content-Length: ' + content.html.length + CRLF;
			result += 'Content-Type: text/html' + CRLF;
		}
	}
	if (content.headers) {
		for (var i in content.headers)
			{result += i + ': ' + content.headers[i] + CRLF;}
	}
	result += CRLF;
	result += content.html || '';
	return result;
};

// very lightweight HTML5 generator; useful?
var createHTML = function(title, body, additionals) {
	var result = '<!DOCTYPE html><html><head><title>' + title + '</title><meta charset="utf-8">', i;
	if (additionals) {
		if (additionals.css) {
			var cssItem;
			for (i = 0; i < additionals.css.length; i++) {
				cssItem = additionals.css[i];
				result += '<link rel="stylesheet" href="';
				if (typeof cssItem == 'string') result += cssItem + '" ';
				else {
					result += cssItem.href + '" ' || '';
					result += 'media="' + cssItem.mediaType + '" ' || '';
				}
				result += '/>';
			}
		}
		if (additionals.js) {
			for (i = 0; i < additionals.js.length; i++)
				{result += '<script src="' + additionals.js[i] + '"></script>';}
		}
	}
	result += '<body>' + body + '</body></html>';
	return result;
};

var statusCat = function(statusCode, statusText) {
	return '<div style="text-align:center;"><img src="http://httpcats.herokuapp.com/' + statusCode +
		'.jpg" alt="404" height="500"/><div>' + statusText + '</div></div>';
};

var responses = {
	'https-established': {
		statusCode: 200,
		reasonPhrase: 'Connection established',
		headers: {'Connection': 'Keep-Alive'},
		noDefaultHeaders: true
	},
	'host-blacklisted': {
		statusCode: 502,
		reasonPhrase: 'Bad Gateway',
		html: createHTML('502 Bad Gateway', statusCat(502, "This mass relay does not accept Cerberus payloads."))
	},
	'decline-http': {
		statusCode: 502,
		reasonPhrase: 'Bad Gateway',
		html: createHTML('502 Bad Gateway', statusCat(502, "This mass relay does not accept Cerberus payloads."))
	},
	'/': {
		statusCode: 418,
		reasonPhrase: "I'm a teapot",
		html: createHTML('Nodejs SPDY Proxy Server', common.about.replace(/\n/g, '<br/>') + "<hr/>")
	},
	'request-timeout': {
		statusCode: 504,
		reasonPhrase: 'Gateway Timeout',
		html: createHTML('504 Gateway Timeout', statusCat(504, 'Your Request has timeout. You may try again or get a life.'))
	},
	'illegal-response': {
		statusCode: 502,
		reasonPhrase: 'Bad Gateway',
		html: createHTML('502 Bad Gateway', statusCat(502, "We received an invalid response from the server. Maybe it's running off a Raspberry PI."))
	},
	'ECONNREFUSED': {
		statusCode: 502,
		reasonPhrase: 'Bad Gateway',
		html: createHTML('502 Bad Gateway', statusCat(502, "ECONNREFUSED. GLaDOS said no."))
	},
	'ENOTFOUND': {
		statusCode: 400,
		reasonPhrase: 'Bad Request',
		html: createHTML('400 Bad Request', statusCat(400, "ENOTFOUND. Chuck Norris doesn't call the wrong number. You answer the wrong phone."))
	},
	'ECONNRESET': {
		statusCode: 502,
		reasonPhrase: 'Bad Gateway',
		html: createHTML('502 Bad Gateway', statusCat(502, "ECONNRESET. Me suppose this is what you get for supporting SOPA/PIPA."))
	},
	'default': {
		statusCode: 404,
		reasonPhrase: 'Not Found',
		html: createHTML('404 File Not Found', statusCat(404, 'The Creepers have taken over the Internet. Sssssssssssorry about that.'))
	}
};