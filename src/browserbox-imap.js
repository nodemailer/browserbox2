// Copyright (c) 2014 Andris Reinman

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

'use strict';

const SOCKET_TIMEOUT = 10 * 60 * 1000;

const net = require('net');
const tls = require('tls');
const imapHandler = require('wo-imap-handler');
const shared = require('nodemailer/lib/shared');
const crypto = require('crypto');

/**
 * Creates a connection object to an IMAP server. Call `connect` method to inititate
 * the actual connection, the constructor only defines the properties but does not actually connect.
 *
 * @constructor
 *
 * @param {String} [host='localhost'] Hostname to conenct to
 * @param {Number} [port=143] Port number to connect to
 * @param {Object} [options] Optional options object
 * @param {Boolean} [options.useSecureTransport] Set to true, to use encrypted connection
 */
function ImapClient(host, port, options) {
    this.options = options || {};

    this.id = crypto
        .randomBytes(8)
        .toString('base64')
        .replace(/\W/g, '');

    this.port = port || (this.options.useSecureTransport ? 993 : 143);
    this.host = host || 'localhost';

    /**
     * If set to true, start an encrypted connection instead of the plaintext one
     * (recommended if applicable). If useSecureTransport is not set but the port used is 993,
     * then ecryption is used by default.
     */
    this.options.useSecureTransport = 'useSecureTransport' in this.options ? !!this.options.useSecureTransport : this.port === 993;

    /**
     * Authentication object. If not set, authentication step will be skipped.
     */
    this.options.auth = this.options.auth || false;

    /**
     * Downstream TCP socket to the IMAP server, created with TCPSocket
     */
    this.socket = false;

    /**
     * Indicates if the connection has been closed and can't be used anymore
     *
     */
    this.destroyed = false;

    /**
     * Keeps track if the downstream socket is currently full and
     * a drain event should be waited for or not
     */
    this.waitDrain = false;

    // Private properties

    /**
     * Does the connection use SSL/TLS
     */
    this.secureMode = !!this.options.useSecureTransport;

    /**
     * Is the conection established and greeting is received from the server
     */
    this._connectionReady = false;

    /**
     * As the server sends data in chunks, it needs to be split into
     * separate lines. These variables help with parsing the input.
     */
    this._remainder = '';
    this._command = '';
    this._literalRemaining = 0;

    /**
     * Is there something being processed
     */
    this._processingServerData = false;

    /**
     * Queue of received commands
     */
    this._serverQueue = [];

    /**
     * Is it OK to send something to the server
     */
    this._canSend = false;

    /**
     * Queue of outgoing commands
     */
    this._clientQueue = [];

    /**
     * Counter to allow uniqueue imap tags
     */
    this._tagCounter = 0;

    /**
     * Current command that is waiting for response from the server
     */
    this._currentCommand = false;

    /**
     * Global handlers for unrelated responses (EXPUNGE, EXISTS etc.)
     */
    this._globalAcceptUntagged = {};

    /**
     * Timer waiting to enter idle
     */
    this._idleTimer = false;

    this.logger = shared.getLogger(this.options, {
        component: this.options.component || 'imap-connection',
        sid: this.id
    });
}

// Constants

/**
 * How much time to wait since the last response until the connection is considered idling
 */
ImapClient.prototype.TIMEOUT_ENTER_IDLE = 1000;

/**
 * Lower Bound for socket timeout to wait since the last data was written to a socket
 */
ImapClient.prototype.TIMEOUT_SOCKET_LOWER_BOUND = 10000;

/**
 * Multiplier for socket timeout:
 *
 * We assume at least a GPRS connection with 115 kb/s = 14,375 kB/s tops, so 10 KB/s to be on
 * the safe side. We can timeout after a lower bound of 10s + (n KB / 10 KB/s). A 1 MB message
 * upload would be 110 seconds to wait for the timeout. 10 KB/s === 0.1 s/B
 */
ImapClient.prototype.TIMEOUT_SOCKET_MULTIPLIER = 0.1;

// PUBLIC EVENTS
// Event functions should be overriden, these are just placeholders

/**
 * Will be run when an error occurs. Connection to the server will be closed automatically,
 * so wait for an `onclose` event as well.
 *
 * @event
 * @param {Error} err Error object
 */
ImapClient.prototype.onerror = function() {};

/**
 * More data can be buffered in the socket. See `waitDrain` property or
 * check if `send` method returns false to see if you should be waiting
 * for the drain event.
 *
 * @event
 */
ImapClient.prototype.ondrain = function() {};

/**
 * The connection to the server has been closed
 *
 * @event
 */
ImapClient.prototype.onclose = function() {};

/**
 * The connection to the server has been established and greeting is received
 *
 * @event
 */
ImapClient.prototype.onready = function() {};

/**
 * There are no more commands to process
 *
 * @event
 */
ImapClient.prototype.onidle = function() {};

// PUBLIC METHODS

/**
 * Initiate a connection to the server. Wait for onready event
 */
ImapClient.prototype.connect = function() {
    let opts = {
        port: this.port,
        host: this.host
    };

    let tcpHandler = this.options.useSecureTransport ? tls : net;
    Object.keys(this.options.tls || {}).forEach(key => {
        opts[key] = this.options.tls[key];
    });

    this.socket = tcpHandler.connect(opts, () => {
        if (this.socket.authorizationError) {
            this.logger.error(
                { tnx: 'starttls', err: new Error(this.socket.authorizationError) },
                `Server certificate verification failed (${this.socket.authorizationError})`
            );
        }
        this._onOpen();
    });

    this.socket.on('error', err => this._onError(err));

    this.onSocketTimeout = (...args) => this._onTimeout(...args);
    this.socket.setTimeout(SOCKET_TIMEOUT);
    this.socket.on('timeout', this.onSocketTimeout);
};

/**
 * Closes the connection to the server
 */
ImapClient.prototype.close = function() {
    if (!this.socket.destroyed && this.socket.writable) {
        this.socket.end();
    } else {
        this._destroy();
    }
};

/**
 * Closes the connection to the server
 */
ImapClient.prototype.upgrade = function(callback) {
    if (this.secureMode || this.secure) {
        return callback(null, false);
    }

    // we can safely keep 'error', 'end', 'close' etc. events
    this.socket.removeListener('data', this.onSocketData); // incoming data is going to be gibberish from this point onwards
    this.socket.removeListener('timeout', this.onSocketTimeout); // timeout will be re-set for the new socket object

    let socketPlain = this.socket;
    let opts = {
        socket: this.socket,
        host: this.host
    };

    Object.keys(this.options.tls || {}).forEach(key => {
        opts[key] = this.options.tls[key];
    });

    this.upgrading = true;
    this.socket = tls.connect(opts, () => {
        this.secure = true;
        this.upgrading = false;

        if (this.socket.authorizationError) {
            this.logger.error(
                { tnx: 'starttls', err: new Error(this.socket.authorizationError) },
                `Server certificate verification failed (${this.socket.authorizationError})`
            );
        }

        this.socket.on('data', this.onSocketData);
        socketPlain.removeListener('close', this.onSocketClose);

        return callback(null, true);
    });

    this.socket.on('error', err => this._onError(err));
    this.socket.once('close', this.onSocketClose);

    this.socket.setTimeout(SOCKET_TIMEOUT); // 10 min.
    this.socket.on('timeout', this.onSocketTimeout);

    // resume in case the socket was paused
    socketPlain.resume();
};

/**
 * Schedules a command to be sent to the server. This method is chainable.
 * See https://github.com/Kreata/imapHandler for request structure.
 * Do not provide a tag property, it will be set byt the queue manager.
 *
 * To catch untagged responses use acceptUntagged property. For example, if
 * the value for it is 'FETCH' then the reponse includes 'payload.FETCH' property
 * that is an array including all listed * FETCH responses.
 *
 * Callback function provides 2 arguments, parsed response object and continue callback.
 *
 *   function(response, next){
 *     console.log(response);
 *     next();
 *   }
 *
 * @param {Object} request Structured request object
 * @param {Array} acceptUntagged a list of untagged responses that will be included in 'payload' property
 * @param {Object} [options] Optional data for the command payload, eg. {onplustagged: function(response, next){next();}}
 * @param {Function} callback Callback function to run once the command has been processed
 */
ImapClient.prototype.exec = function(request, acceptUntagged, options, callback) {
    if (typeof request === 'string') {
        request = {
            command: request
        };
    }
    this._addToClientQueue(request, acceptUntagged, options, callback);
    return this;
};

/**
 * Send data to the TCP socket
 * Arms a timeout waiting for a response from the server.
 *
 * @param {String} str Payload
 */
ImapClient.prototype.send = function(str) {
    let buffer = Buffer.from(str);
    this.waitDrain = !this.socket.write(buffer);
};

/**
 * Set a global handler for an untagged response. If currently processed command
 * has not listed untagged command it is forwarded to the global handler. Useful
 * with EXPUNGE, EXISTS etc.
 *
 * @param {String} command Untagged command name
 * @param {Function} callback Callback function with response object and continue callback function
 */
ImapClient.prototype.setHandler = function(command, callback) {
    this._globalAcceptUntagged[
        (command || '')
            .toString()
            .toUpperCase()
            .trim()
    ] = callback;
};

// INTERNAL EVENTS

/**
 * Error handler for the socket
 *
 * @event
 * @param {Event} evt Event object. See evt.data for the error
 */
ImapClient.prototype._onError = function(err) {
    this.logger.error({ tnx: 'imap', cid: this.id, err }, err.message);
    this.onerror(err);
    this.close();
};

/**
 * Ensures that the connection is closed
 */
ImapClient.prototype._destroy = function() {
    this._serverQueue = [];
    this._clientQueue = [];
    this._currentCommand = false;

    clearTimeout(this._idleTimer);

    if (!this.destroyed) {
        this.destroyed = true;
        this.onclose();
    }
};

/**
 * Indicates that the socket has been closed
 *
 * @event
 * @param {Event} evt Event object. Not used
 */
ImapClient.prototype._onClose = function() {
    this._destroy();
};

/**
 * Indicates that a socket timeout has occurred
 */
ImapClient.prototype._onTimeout = function() {
    // inform about the timeout, _onError takes case of the rest
    let err = new Error('Socket timed out!');
    this._onError(err);
};

/**
 * More data can be buffered in the socket, `waitDrain` is reset to false
 *
 * @event
 * @param {Event} evt Event object. Not used
 */
ImapClient.prototype._onDrain = function() {
    this.waitDrain = false;
    this.ondrain();
};

/**
 * Handler for incoming data from the server. The data is sent in arbitrary
 * chunks and can't be used directly so this function makes sure the data
 * is split into complete lines before the data is passed to the command
 * handler
 *
 * @param {Event} evt
 */
ImapClient.prototype._onData = function(chunk) {
    let match,
        str = chunk.toString('binary');

    if (this._literalRemaining) {
        if (this._literalRemaining > str.length) {
            this._literalRemaining -= str.length;
            this._command += str;
            return;
        }
        this._command += str.substr(0, this._literalRemaining);
        str = str.substr(this._literalRemaining);
        this._literalRemaining = 0;
    }
    this._remainder = str = this._remainder + str;
    while ((match = str.match(/(\{(\d+)(\+)?\})?\r?\n/))) {
        if (!match[2]) {
            // Now we have a full command line, so lets do something with it
            this._addToServerQueue(this._command + str.substr(0, match.index));

            this._remainder = str = str.substr(match.index + match[0].length);
            this._command = '';
            continue;
        }

        this._remainder = '';

        this._command += str.substr(0, match.index + match[0].length);

        this._literalRemaining = Number(match[2]);

        str = str.substr(match.index + match[0].length);

        if (this._literalRemaining > str.length) {
            this._command += str;
            this._literalRemaining -= str.length;
            return;
        } else {
            this._command += str.substr(0, this._literalRemaining);
            this._remainder = str = str.substr(this._literalRemaining);
            this._literalRemaining = 0;
        }
    }
};

/**
 * Connection listener that is run when the connection to the server is opened.
 * Sets up different event handlers for the opened socket
 *
 * @event
 */
ImapClient.prototype._onOpen = function() {
    this.logger.info({ tnx: 'imap', cid: this.id }, `TCP socket opened to ${this.host}:${this.port}`);

    this.onSocketData = (...args) => this._onData(...args);
    this.onSocketClose = (...args) => this._onClose(...args);

    this.socket.on('data', this.onSocketData);
    this.socket.on('close', this.onSocketClose);
};

// PRIVATE METHODS

/**
 * Pushes command line from the server to the server processing queue. If the
 * processor is idle, start processing.
 *
 * @param {String} cmd Command line
 */
ImapClient.prototype._addToServerQueue = function(cmd) {
    this._serverQueue.push(cmd);

    if (this._processingServerData) {
        return;
    }

    this._processingServerData = true;
    this._processServerQueue();
};

/**
 * Process a command from the queue. The command is parsed and feeded to a handler
 */
ImapClient.prototype._processServerQueue = function() {
    if (!this._serverQueue.length) {
        this._processingServerData = false;
        return;
    } else {
        this._clearIdle();
    }

    let data = this._serverQueue.shift(),
        response;

    try {
        // + tagged response is a special case, do not try to parse it
        if (/^\+/.test(data)) {
            response = {
                tag: '+',
                payload: data.substr(2) || ''
            };
        } else {
            response = imapHandler.parser(data);
            this.logger.info({ tnx: 'imap', cid: this.id }, 'S: ' + imapHandler.compiler(response, false, true));
        }
    } catch (err) {
        this.logger.info({ tnx: 'imap', cid: this.id }, 'Error parsing IMAP data:\n' + data);
        return this._onError(err);
    }

    if (response.tag === '*' && /^\d+$/.test(response.command) && response.attributes && response.attributes.length && response.attributes[0].type === 'ATOM') {
        response.nr = Number(response.command);
        response.command = (response.attributes.shift().value || '')
            .toString()
            .toUpperCase()
            .trim();
    }

    // feed the next chunk to the server if a + tagged response was received
    if (response.tag === '+') {
        if (this._currentCommand.data.length) {
            data = this._currentCommand.data.shift();
            this.send(data + (!this._currentCommand.data.length ? '\r\n' : ''));
        } else if (typeof this._currentCommand.onplustagged === 'function') {
            this._currentCommand.onplustagged(response, this._processServerQueue.bind(this));
            return;
        }
        setTimeout(this._processServerQueue.bind(this), 0);
        return;
    }

    this._processServerResponse(
        response,
        function(err) {
            if (err) {
                return this._onError(err);
            }

            // first response from the server, connection is now usable
            if (!this._connectionReady) {
                this._connectionReady = true;
                this.onready();
                this._canSend = true;
                this._sendRequest();
            } else if (response.tag !== '*') {
                // allow sending next command after full response
                this._canSend = true;
                this._sendRequest();
            }

            setTimeout(this._processServerQueue.bind(this), 0);
        }.bind(this)
    );
};

/**
 * Feeds a parsed response object to an appropriate handler
 *
 * @param {Object} response Parsed command object
 * @param {Function} callback Continue callback function
 */
ImapClient.prototype._processServerResponse = function(response, callback) {
    let command = ((response && response.command) || '').toUpperCase().trim();

    this._processResponse(response);

    if (!this._currentCommand) {
        if (response.tag === '*' && command in this._globalAcceptUntagged) {
            return this._globalAcceptUntagged[command](response, callback);
        } else {
            return callback();
        }
    }

    if (this._currentCommand.payload && response.tag === '*' && command in this._currentCommand.payload) {
        this._currentCommand.payload[command].push(response);
        return callback();
    } else if (response.tag === '*' && command in this._globalAcceptUntagged) {
        this._globalAcceptUntagged[command](response, callback);
    } else if (response.tag === this._currentCommand.tag) {
        if (typeof this._currentCommand.callback === 'function') {
            if (this._currentCommand.payload && Object.keys(this._currentCommand.payload).length) {
                response.payload = this._currentCommand.payload;
            }

            return this._currentCommand.callback(response, callback);
        } else {
            return callback();
        }
    } else {
        // Unexpected response
        return callback();
    }
};

/**
 * Adds a request object to outgoing queue. And if data can be sent to the server,
 * the command is executed
 *
 * @param {Object} request Structured request object
 * @param {Array} [acceptUntagged] a list of untagged responses that will be included in 'payload' property
 * @param {Object} [options] Optional data for the command payload, eg. {onplustagged: function(response, next){next();}}
 * @param {Function} callback Callback function to run once the command has been processed
 */
ImapClient.prototype._addToClientQueue = function(request, acceptUntagged, options, callback) {
    let tag = 'W' + ++this._tagCounter,
        data;

    if (!callback && typeof options === 'function') {
        callback = options;
        options = undefined;
    }

    if (!callback && typeof acceptUntagged === 'function') {
        callback = acceptUntagged;
        acceptUntagged = undefined;
    }

    acceptUntagged = [].concat(acceptUntagged || []).map(function(untagged) {
        return (untagged || '')
            .toString()
            .toUpperCase()
            .trim();
    });

    request.tag = tag;

    data = {
        tag,
        request,
        payload: acceptUntagged.length ? {} : undefined,
        callback
    };

    // apply any additional options to the command
    Object.keys(options || {}).forEach(function(key) {
        data[key] = options[key];
    });

    acceptUntagged.forEach(function(command) {
        data.payload[command] = [];
    });

    // if we're in priority mode (i.e. we ran commands in a precheck),
    // queue any commands BEFORE the command that contianed the precheck,
    // otherwise just queue command as usual
    let index = data.ctx ? this._clientQueue.indexOf(data.ctx) : -1;
    if (index >= 0) {
        data.tag += '.p';
        data.request.tag += '.p';
        this._clientQueue.splice(index, 0, data);
    } else {
        this._clientQueue.push(data);
    }

    if (this._canSend) {
        this._sendRequest();
    }
};

/**
 * Sends a command from client queue to the server.
 */
ImapClient.prototype._sendRequest = function() {
    if (!this._clientQueue.length) {
        return this._enterIdle();
    }
    this._clearIdle();

    // an operation was made in the precheck, no need to restart the queue manually
    this._restartQueue = false;

    let command = this._clientQueue[0];
    if (typeof command.precheck === 'function') {
        // remember the context
        let context = command;
        let precheck = context.precheck;
        delete context.precheck;

        // we need to restart the queue handling if no operation was made in the precheck
        this._restartQueue = true;

        // invoke the precheck command with a callback to signal that you're
        // done with precheck and ready to resume normal operation
        precheck(
            context,
            function(err) {
                // we're done with the precheck
                if (!err) {
                    if (this._restartQueue) {
                        // we need to restart the queue handling
                        this._sendRequest();
                    }
                    return;
                }

                // precheck callback failed, so we remove the initial command
                // from the queue, invoke its callback and resume normal operation
                let cmd,
                    index = this._clientQueue.indexOf(context);
                if (index >= 0) {
                    cmd = this._clientQueue.splice(index, 1)[0];
                }
                if (cmd && cmd.callback) {
                    cmd.callback(
                        err,
                        function() {
                            this._canSend = true;
                            this._sendRequest();
                            setTimeout(this._processServerQueue.bind(this), 0);
                        }.bind(this)
                    );
                }
            }.bind(this)
        );
        return;
    }

    this._canSend = false;
    this._currentCommand = this._clientQueue.shift();
    let loggedCommand = false;

    try {
        this._currentCommand.data = imapHandler.compiler(this._currentCommand.request, true);
        loggedCommand = imapHandler.compiler(this._currentCommand.request, false, true);
    } catch (err) {
        this.logger.info({ tnx: 'imap', cid: this.id }, 'Error compiling imap command:\n' + this._currentCommand.request);
        return this._onError(err);
    }

    this.logger.info({ tnx: 'imap', cid: this.id }, 'C: ' + loggedCommand);
    let data = this._currentCommand.data.shift();

    this.send(data + (!this._currentCommand.data.length ? '\r\n' : ''));
    return this.waitDrain;
};

/**
 * Emits onidle, noting to do currently
 */
ImapClient.prototype._enterIdle = function() {
    clearTimeout(this._idleTimer);
    this._idleTimer = setTimeout(
        function() {
            this.onidle();
        }.bind(this),
        this.TIMEOUT_ENTER_IDLE
    );
};

/**
 * Cancel idle timer
 */
ImapClient.prototype._clearIdle = function() {
    clearTimeout(this._idleTimer);
};

// HELPER FUNCTIONS

/**
 * Method checks if a response includes optional response codes
 * and copies these into separate properties. For example the
 * following response includes a capability listing and a human
 * readable message:
 *
 *     * OK [CAPABILITY ID NAMESPACE] All ready
 *
 * This method adds a 'capability' property with an array value ['ID', 'NAMESPACE']
 * to the response object. Additionally 'All ready' is added as 'humanReadable' property.
 *
 * See possiblem IMAP Response Codes at https://tools.ietf.org/html/rfc5530
 *
 * @param {Object} response Parsed response object
 */
ImapClient.prototype._processResponse = function(response) {
    let command = ((response && response.command) || '')
            .toString()
            .toUpperCase()
            .trim(),
        option,
        key;

    if (['OK', 'NO', 'BAD', 'BYE', 'PREAUTH'].indexOf(command) >= 0) {
        // Check if the response includes an optional response code
        if (
            (option =
                response &&
                response.attributes &&
                response.attributes.length &&
                response.attributes[0].type === 'ATOM' &&
                response.attributes[0].section &&
                response.attributes[0].section.map(function(key) {
                    if (!key) {
                        return;
                    }
                    if (Array.isArray(key)) {
                        return key.map(function(key) {
                            return (key.value || '').toString().trim();
                        });
                    } else {
                        return (key.value || '')
                            .toString()
                            .toUpperCase()
                            .trim();
                    }
                }))
        ) {
            key = option && option.shift();

            response.code = key;

            if (option.length) {
                option = [].concat(option || []);
                response[key.toLowerCase()] = option.length === 1 ? option[0] : option;
            }
        }

        // If last element of the response is TEXT then this is for humans
        if (response && response.attributes && response.attributes.length && response.attributes[response.attributes.length - 1].type === 'TEXT') {
            response.humanReadable = response.attributes[response.attributes.length - 1].value;
        }
    }
};

/**
 * Checks if a value is an Error object
 *
 * @param {Mixed} value Value to be checked
 * @return {Boolean} returns true if the value is an Error
 */
ImapClient.prototype.isError = function(value) {
    return !!Object.prototype.toString.call(value).match(/Error\]$/);
};

module.exports = ImapClient;
