/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-mixed-operators, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars, default-case, jsdoc/require-param*/
"use strict";

var $protobuf = require("protobufjs/minimal");

// Common aliases
var $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;
var $Object = $util.global.Object, $undefined = $util.global.undefined, $Error = $util.global.Error, $TypeError = $util.global.TypeError, $String = $util.global.String, $Array = $util.global.Array;

// Exported root namespace
var $root = $protobuf.roots["default"] || ($protobuf.roots["default"] = {});

$root.extensions = (function() {

    /**
     * Namespace extensions.
     * @exports extensions
     * @namespace
     */
    var extensions = {};

    extensions.api = (function() {

        /**
         * Namespace api.
         * @memberof extensions
         * @namespace
         */
        var api = {};

        api.cast_channel = (function() {

            /**
             * Namespace cast_channel.
             * @memberof extensions.api
             * @namespace
             */
            var cast_channel = {};

            cast_channel.CastMessage = (function() {

                /**
                 * Properties of a CastMessage.
                 * @typedef {Object} extensions.api.cast_channel.CastMessage.$Properties
                 * @property {extensions.api.cast_channel.CastMessage.ProtocolVersion} protocolVersion CastMessage protocolVersion
                 * @property {string} sourceId CastMessage sourceId
                 * @property {string} destinationId CastMessage destinationId
                 * @property {string} namespace CastMessage namespace
                 * @property {extensions.api.cast_channel.CastMessage.PayloadType} payloadType CastMessage payloadType
                 * @property {string|null} [payloadUtf8] CastMessage payloadUtf8
                 * @property {Uint8Array|null} [payloadBinary] CastMessage payloadBinary
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */

                /**
                 * Properties of a CastMessage.
                 * @memberof extensions.api.cast_channel
                 * @interface ICastMessage
                 * @augments extensions.api.cast_channel.CastMessage.$Properties
                 * @deprecated Use extensions.api.cast_channel.CastMessage.$Properties instead.
                 */

                /**
                 * Shape of a CastMessage.
                 * @typedef {extensions.api.cast_channel.CastMessage.$Properties} extensions.api.cast_channel.CastMessage.$Shape
                 */

                /**
                 * Constructs a new CastMessage.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents a CastMessage.
                 * @constructor
                 * @param {extensions.api.cast_channel.CastMessage.$Properties=} [properties] Properties to set
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */
                var CastMessage = function (properties) {
                    if (properties)
                        for (var keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null && keys[i] !== "__proto__")
                                this[keys[i]] = properties[keys[i]];
                };

                /**
                 * CastMessage protocolVersion.
                 * @member {extensions.api.cast_channel.CastMessage.ProtocolVersion} protocolVersion
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.protocolVersion = 0;

                /**
                 * CastMessage sourceId.
                 * @member {string} sourceId
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.sourceId = "";

                /**
                 * CastMessage destinationId.
                 * @member {string} destinationId
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.destinationId = "";

                /**
                 * CastMessage namespace.
                 * @member {string} namespace
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.namespace = "";

                /**
                 * CastMessage payloadType.
                 * @member {extensions.api.cast_channel.CastMessage.PayloadType} payloadType
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.payloadType = 0;

                /**
                 * CastMessage payloadUtf8.
                 * @member {string} payloadUtf8
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.payloadUtf8 = "";

                /**
                 * CastMessage payloadBinary.
                 * @member {Uint8Array} payloadBinary
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 */
                CastMessage.prototype.payloadBinary = $util.newBuffer([]);

                /**
                 * Creates a new CastMessage instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {extensions.api.cast_channel.CastMessage.$Properties=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.CastMessage} CastMessage instance
                 * @type {{
                 *   (properties: extensions.api.cast_channel.CastMessage.$Shape): extensions.api.cast_channel.CastMessage & extensions.api.cast_channel.CastMessage.$Shape;
                 *   (properties?: extensions.api.cast_channel.CastMessage.$Properties): extensions.api.cast_channel.CastMessage;
                 * }}
                 */
                CastMessage.create = function(properties) {
                    return new CastMessage(properties);
                };

                /**
                 * Encodes the specified CastMessage message. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {extensions.api.cast_channel.CastMessage.$Properties} message CastMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                CastMessage.encode = function (message, writer, _depth) {
                    if (!writer)
                        writer = $Writer.create();
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    writer.uint32(/* id 1, wireType 0 =*/8).int32(message.protocolVersion);
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.sourceId);
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.destinationId);
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.namespace);
                    writer.uint32(/* id 5, wireType 0 =*/40).int32(message.payloadType);
                    if (message.payloadUtf8 != null && $Object.hasOwnProperty.call(message, "payloadUtf8"))
                        writer.uint32(/* id 6, wireType 2 =*/50).string(message.payloadUtf8);
                    if (message.payloadBinary != null && $Object.hasOwnProperty.call(message, "payloadBinary"))
                        writer.uint32(/* id 7, wireType 2 =*/58).bytes(message.payloadBinary);
                    if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                        for (var i = 0; i < message.$unknowns.length; ++i)
                            writer.raw(message.$unknowns[i]);
                    return writer;
                };

                /**
                 * Encodes the specified CastMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {extensions.api.cast_channel.CastMessage.$Properties} message CastMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                CastMessage.encodeDelimited = function(message, writer) {
                    return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
                };

                /**
                 * Decodes a CastMessage message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.CastMessage & extensions.api.cast_channel.CastMessage.$Shape} CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                CastMessage.decode = function (reader, length, _end, _depth, _target) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $Reader.recursionLimit)
                        throw $Error("max depth exceeded");
                    var end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.extensions.api.cast_channel.CastMessage();
                    while (reader.pos < end) {
                        var start = reader.pos;
                        var tag = reader.tag();
                        if (tag === _end) {
                            _end = $undefined;
                            break;
                        }
                        var wireType = tag & 7;
                        switch (tag >>>= 3) {
                        case 1: {
                                if (wireType !== 0)
                                    break;
                                message.protocolVersion = reader.int32();
                                continue;
                            }
                        case 2: {
                                if (wireType !== 2)
                                    break;
                                message.sourceId = reader.string();
                                continue;
                            }
                        case 3: {
                                if (wireType !== 2)
                                    break;
                                message.destinationId = reader.string();
                                continue;
                            }
                        case 4: {
                                if (wireType !== 2)
                                    break;
                                message.namespace = reader.string();
                                continue;
                            }
                        case 5: {
                                if (wireType !== 0)
                                    break;
                                message.payloadType = reader.int32();
                                continue;
                            }
                        case 6: {
                                if (wireType !== 2)
                                    break;
                                message.payloadUtf8 = reader.string();
                                continue;
                            }
                        case 7: {
                                if (wireType !== 2)
                                    break;
                                message.payloadBinary = reader.bytes();
                                continue;
                            }
                        }
                        reader.skipType(wireType, _depth, tag);
                        if (!reader.discardUnknown) {
                            $util.makeProp(message, "$unknowns", false);
                            (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                        }
                    }
                    if (_end !== $undefined)
                        throw $Error("missing end group");
                    if (!$Object.hasOwnProperty.call(message, "protocolVersion"))
                        throw $util.ProtocolError("missing required 'protocolVersion'", { instance: message });
                    if (!$Object.hasOwnProperty.call(message, "sourceId"))
                        throw $util.ProtocolError("missing required 'sourceId'", { instance: message });
                    if (!$Object.hasOwnProperty.call(message, "destinationId"))
                        throw $util.ProtocolError("missing required 'destinationId'", { instance: message });
                    if (!$Object.hasOwnProperty.call(message, "namespace"))
                        throw $util.ProtocolError("missing required 'namespace'", { instance: message });
                    if (!$Object.hasOwnProperty.call(message, "payloadType"))
                        throw $util.ProtocolError("missing required 'payloadType'", { instance: message });
                    return message;
                };

                /**
                 * Decodes a CastMessage message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.CastMessage & extensions.api.cast_channel.CastMessage.$Shape} CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                CastMessage.decodeDelimited = function(reader) {
                    if (!(reader instanceof $Reader))
                        reader = new $Reader(reader);
                    return this.decode(reader, reader.uint32());
                };

                /**
                 * Verifies a CastMessage message.
                 * @function verify
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {Object.<string,*>} message Plain object to verify
                 * @returns {string|null} `null` if valid, otherwise the reason why it is not
                 */
                CastMessage.verify = function (message, _depth) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        return "max depth exceeded";
                    switch (message.protocolVersion) {
                    default:
                        return "protocolVersion: enum value expected";
                    case 0:
                        break;
                    }
                    if (!$util.isString(message.sourceId))
                        return "sourceId: string expected";
                    if (!$util.isString(message.destinationId))
                        return "destinationId: string expected";
                    if (!$util.isString(message.namespace))
                        return "namespace: string expected";
                    switch (message.payloadType) {
                    default:
                        return "payloadType: enum value expected";
                    case 0:
                    case 1:
                        break;
                    }
                    if (message.payloadUtf8 != null && $Object.hasOwnProperty.call(message, "payloadUtf8"))
                        if (!$util.isString(message.payloadUtf8))
                            return "payloadUtf8: string expected";
                    if (message.payloadBinary != null && $Object.hasOwnProperty.call(message, "payloadBinary"))
                        if (!(message.payloadBinary && typeof message.payloadBinary.length === "number" || $util.isString(message.payloadBinary)))
                            return "payloadBinary: buffer expected";
                    return null;
                };

                /**
                 * Creates a CastMessage message from a plain object. Also converts values to their respective internal types.
                 * @function fromObject
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {Object.<string,*>} object Plain object
                 * @returns {extensions.api.cast_channel.CastMessage} CastMessage
                 */
                CastMessage.fromObject = function (object, _depth) {
                    if (object instanceof $root.extensions.api.cast_channel.CastMessage)
                        return object;
                    if (!$util.isObject(object))
                        throw $TypeError(".extensions.api.cast_channel.CastMessage: object expected");
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var message = new $root.extensions.api.cast_channel.CastMessage();
                    switch (object.protocolVersion) {
                    default:
                        if (typeof object.protocolVersion === "number") {
                            message.protocolVersion = object.protocolVersion;
                            break;
                        }
                        break;
                    case "CASTV2_1_0":
                    case 0:
                        message.protocolVersion = 0;
                        break;
                    }
                    if (object.sourceId != null)
                        message.sourceId = $String(object.sourceId);
                    if (object.destinationId != null)
                        message.destinationId = $String(object.destinationId);
                    if (object.namespace != null)
                        message.namespace = $String(object.namespace);
                    switch (object.payloadType) {
                    default:
                        if (typeof object.payloadType === "number") {
                            message.payloadType = object.payloadType;
                            break;
                        }
                        break;
                    case "STRING":
                    case 0:
                        message.payloadType = 0;
                        break;
                    case "BINARY":
                    case 1:
                        message.payloadType = 1;
                        break;
                    }
                    if (object.payloadUtf8 != null)
                        message.payloadUtf8 = $String(object.payloadUtf8);
                    if (object.payloadBinary != null)
                        if (typeof object.payloadBinary === "string")
                            $util.base64.decode(object.payloadBinary, message.payloadBinary = $util.newBuffer($util.base64.length(object.payloadBinary)), 0);
                        else if (object.payloadBinary.length >= 0)
                            message.payloadBinary = object.payloadBinary;
                    return message;
                };

                /**
                 * Creates a plain object from a CastMessage message. Also converts values to other types if specified.
                 * @function toObject
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {extensions.api.cast_channel.CastMessage} message CastMessage
                 * @param {$protobuf.IConversionOptions} [options] Conversion options
                 * @returns {Object.<string,*>} Plain object
                 */
                CastMessage.toObject = function (message, options, _depth) {
                    if (!options)
                        options = {};
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var object = {};
                    if (options.defaults) {
                        object.protocolVersion = options.enums === $String ? "CASTV2_1_0" : 0;
                        object.sourceId = "";
                        object.destinationId = "";
                        object.namespace = "";
                        object.payloadType = options.enums === $String ? "STRING" : 0;
                        object.payloadUtf8 = "";
                        if (options.bytes === $String)
                            object.payloadBinary = "";
                        else {
                            object.payloadBinary = [];
                            if (options.bytes !== $Array)
                                object.payloadBinary = $util.newBuffer(object.payloadBinary);
                        }
                    }
                    if (message.protocolVersion != null && $Object.hasOwnProperty.call(message, "protocolVersion"))
                        object.protocolVersion = options.enums === $String ? $root.extensions.api.cast_channel.CastMessage.ProtocolVersion[message.protocolVersion] === $undefined ? message.protocolVersion : $root.extensions.api.cast_channel.CastMessage.ProtocolVersion[message.protocolVersion] : message.protocolVersion;
                    if (message.sourceId != null && $Object.hasOwnProperty.call(message, "sourceId"))
                        object.sourceId = message.sourceId;
                    if (message.destinationId != null && $Object.hasOwnProperty.call(message, "destinationId"))
                        object.destinationId = message.destinationId;
                    if (message.namespace != null && $Object.hasOwnProperty.call(message, "namespace"))
                        object.namespace = message.namespace;
                    if (message.payloadType != null && $Object.hasOwnProperty.call(message, "payloadType"))
                        object.payloadType = options.enums === $String ? $root.extensions.api.cast_channel.CastMessage.PayloadType[message.payloadType] === $undefined ? message.payloadType : $root.extensions.api.cast_channel.CastMessage.PayloadType[message.payloadType] : message.payloadType;
                    if (message.payloadUtf8 != null && $Object.hasOwnProperty.call(message, "payloadUtf8"))
                        object.payloadUtf8 = message.payloadUtf8;
                    if (message.payloadBinary != null && $Object.hasOwnProperty.call(message, "payloadBinary"))
                        object.payloadBinary = options.bytes === $String ? $util.base64.encode(message.payloadBinary, 0, message.payloadBinary.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.payloadBinary) : message.payloadBinary;
                    return object;
                };

                /**
                 * Converts this CastMessage to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                CastMessage.prototype.toJSON = function() {
                    return CastMessage.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the type url for CastMessage
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns {string} The type url
                 */
                CastMessage.getTypeUrl = function(prefix) {
                    if (prefix === $undefined)
                        prefix = "type.googleapis.com";
                    return prefix + "/extensions.api.cast_channel.CastMessage";
                };

                /**
                 * ProtocolVersion enum.
                 * @name extensions.api.cast_channel.CastMessage.ProtocolVersion
                 * @enum {number}
                 * @property {number} CASTV2_1_0=0 CASTV2_1_0 value
                 */
                CastMessage.ProtocolVersion = (function() {
                    var valuesById = {}, values = $Object.create(valuesById);
                    values[valuesById[0] = "CASTV2_1_0"] = 0;
                    return values;
                })();

                /**
                 * PayloadType enum.
                 * @name extensions.api.cast_channel.CastMessage.PayloadType
                 * @enum {number}
                 * @property {number} STRING=0 STRING value
                 * @property {number} BINARY=1 BINARY value
                 */
                CastMessage.PayloadType = (function() {
                    var valuesById = {}, values = $Object.create(valuesById);
                    values[valuesById[0] = "STRING"] = 0;
                    values[valuesById[1] = "BINARY"] = 1;
                    return values;
                })();

                return CastMessage;
            })();

            cast_channel.AuthChallenge = (function() {

                /**
                 * Properties of an AuthChallenge.
                 * @typedef {Object} extensions.api.cast_channel.AuthChallenge.$Properties
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */

                /**
                 * Properties of an AuthChallenge.
                 * @memberof extensions.api.cast_channel
                 * @interface IAuthChallenge
                 * @augments extensions.api.cast_channel.AuthChallenge.$Properties
                 * @deprecated Use extensions.api.cast_channel.AuthChallenge.$Properties instead.
                 */

                /**
                 * Shape of an AuthChallenge.
                 * @typedef {extensions.api.cast_channel.AuthChallenge.$Properties} extensions.api.cast_channel.AuthChallenge.$Shape
                 */

                /**
                 * Constructs a new AuthChallenge.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents an AuthChallenge.
                 * @constructor
                 * @param {extensions.api.cast_channel.AuthChallenge.$Properties=} [properties] Properties to set
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */
                var AuthChallenge = function (properties) {
                    if (properties)
                        for (var keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null && keys[i] !== "__proto__")
                                this[keys[i]] = properties[keys[i]];
                };

                /**
                 * Creates a new AuthChallenge instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.AuthChallenge.$Properties=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.AuthChallenge} AuthChallenge instance
                 * @type {{
                 *   (properties: extensions.api.cast_channel.AuthChallenge.$Shape): extensions.api.cast_channel.AuthChallenge & extensions.api.cast_channel.AuthChallenge.$Shape;
                 *   (properties?: extensions.api.cast_channel.AuthChallenge.$Properties): extensions.api.cast_channel.AuthChallenge;
                 * }}
                 */
                AuthChallenge.create = function(properties) {
                    return new AuthChallenge(properties);
                };

                /**
                 * Encodes the specified AuthChallenge message. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.AuthChallenge.$Properties} message AuthChallenge message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthChallenge.encode = function (message, writer, _depth) {
                    if (!writer)
                        writer = $Writer.create();
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                        for (var i = 0; i < message.$unknowns.length; ++i)
                            writer.raw(message.$unknowns[i]);
                    return writer;
                };

                /**
                 * Encodes the specified AuthChallenge message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.AuthChallenge.$Properties} message AuthChallenge message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthChallenge.encodeDelimited = function(message, writer) {
                    return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
                };

                /**
                 * Decodes an AuthChallenge message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthChallenge & extensions.api.cast_channel.AuthChallenge.$Shape} AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthChallenge.decode = function (reader, length, _end, _depth, _target) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $Reader.recursionLimit)
                        throw $Error("max depth exceeded");
                    var end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.extensions.api.cast_channel.AuthChallenge();
                    while (reader.pos < end) {
                        var start = reader.pos;
                        var tag = reader.tag();
                        if (tag === _end) {
                            _end = $undefined;
                            break;
                        }
                        reader.skipType(tag & 7, _depth, tag);
                        if (!reader.discardUnknown) {
                            $util.makeProp(message, "$unknowns", false);
                            (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                        }
                    }
                    if (_end !== $undefined)
                        throw $Error("missing end group");
                    return message;
                };

                /**
                 * Decodes an AuthChallenge message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthChallenge & extensions.api.cast_channel.AuthChallenge.$Shape} AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthChallenge.decodeDelimited = function(reader) {
                    if (!(reader instanceof $Reader))
                        reader = new $Reader(reader);
                    return this.decode(reader, reader.uint32());
                };

                /**
                 * Verifies an AuthChallenge message.
                 * @function verify
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {Object.<string,*>} message Plain object to verify
                 * @returns {string|null} `null` if valid, otherwise the reason why it is not
                 */
                AuthChallenge.verify = function (message, _depth) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        return "max depth exceeded";
                    return null;
                };

                /**
                 * Creates an AuthChallenge message from a plain object. Also converts values to their respective internal types.
                 * @function fromObject
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {Object.<string,*>} object Plain object
                 * @returns {extensions.api.cast_channel.AuthChallenge} AuthChallenge
                 */
                AuthChallenge.fromObject = function (object, _depth) {
                    if (object instanceof $root.extensions.api.cast_channel.AuthChallenge)
                        return object;
                    if (!$util.isObject(object))
                        throw $TypeError(".extensions.api.cast_channel.AuthChallenge: object expected");
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    return new $root.extensions.api.cast_channel.AuthChallenge();
                };

                /**
                 * Creates a plain object from an AuthChallenge message. Also converts values to other types if specified.
                 * @function toObject
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.AuthChallenge} message AuthChallenge
                 * @param {$protobuf.IConversionOptions} [options] Conversion options
                 * @returns {Object.<string,*>} Plain object
                 */
                AuthChallenge.toObject = function () {
                    return {};
                };

                /**
                 * Converts this AuthChallenge to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                AuthChallenge.prototype.toJSON = function() {
                    return AuthChallenge.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the type url for AuthChallenge
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns {string} The type url
                 */
                AuthChallenge.getTypeUrl = function(prefix) {
                    if (prefix === $undefined)
                        prefix = "type.googleapis.com";
                    return prefix + "/extensions.api.cast_channel.AuthChallenge";
                };

                return AuthChallenge;
            })();

            cast_channel.AuthResponse = (function() {

                /**
                 * Properties of an AuthResponse.
                 * @typedef {Object} extensions.api.cast_channel.AuthResponse.$Properties
                 * @property {Uint8Array} signature AuthResponse signature
                 * @property {Uint8Array} clientAuthCertificate AuthResponse clientAuthCertificate
                 * @property {Array.<Uint8Array>|null} [clientCa] AuthResponse clientCa
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */

                /**
                 * Properties of an AuthResponse.
                 * @memberof extensions.api.cast_channel
                 * @interface IAuthResponse
                 * @augments extensions.api.cast_channel.AuthResponse.$Properties
                 * @deprecated Use extensions.api.cast_channel.AuthResponse.$Properties instead.
                 */

                /**
                 * Shape of an AuthResponse.
                 * @typedef {extensions.api.cast_channel.AuthResponse.$Properties} extensions.api.cast_channel.AuthResponse.$Shape
                 */

                /**
                 * Constructs a new AuthResponse.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents an AuthResponse.
                 * @constructor
                 * @param {extensions.api.cast_channel.AuthResponse.$Properties=} [properties] Properties to set
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */
                var AuthResponse = function (properties) {
                    this.clientCa = [];
                    if (properties)
                        for (var keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null && keys[i] !== "__proto__")
                                this[keys[i]] = properties[keys[i]];
                };

                /**
                 * AuthResponse signature.
                 * @member {Uint8Array} signature
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @instance
                 */
                AuthResponse.prototype.signature = $util.newBuffer([]);

                /**
                 * AuthResponse clientAuthCertificate.
                 * @member {Uint8Array} clientAuthCertificate
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @instance
                 */
                AuthResponse.prototype.clientAuthCertificate = $util.newBuffer([]);

                /**
                 * AuthResponse clientCa.
                 * @member {Array.<Uint8Array>} clientCa
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @instance
                 */
                AuthResponse.prototype.clientCa = $util.emptyArray;

                /**
                 * Creates a new AuthResponse instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {extensions.api.cast_channel.AuthResponse.$Properties=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.AuthResponse} AuthResponse instance
                 * @type {{
                 *   (properties: extensions.api.cast_channel.AuthResponse.$Shape): extensions.api.cast_channel.AuthResponse & extensions.api.cast_channel.AuthResponse.$Shape;
                 *   (properties?: extensions.api.cast_channel.AuthResponse.$Properties): extensions.api.cast_channel.AuthResponse;
                 * }}
                 */
                AuthResponse.create = function(properties) {
                    return new AuthResponse(properties);
                };

                /**
                 * Encodes the specified AuthResponse message. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {extensions.api.cast_channel.AuthResponse.$Properties} message AuthResponse message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthResponse.encode = function (message, writer, _depth) {
                    if (!writer)
                        writer = $Writer.create();
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.signature);
                    writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.clientAuthCertificate);
                    if (message.clientCa != null && message.clientCa.length)
                        for (var i = 0; i < message.clientCa.length; ++i)
                            writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.clientCa[i]);
                    if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                        for (var i = 0; i < message.$unknowns.length; ++i)
                            writer.raw(message.$unknowns[i]);
                    return writer;
                };

                /**
                 * Encodes the specified AuthResponse message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {extensions.api.cast_channel.AuthResponse.$Properties} message AuthResponse message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthResponse.encodeDelimited = function(message, writer) {
                    return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
                };

                /**
                 * Decodes an AuthResponse message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthResponse & extensions.api.cast_channel.AuthResponse.$Shape} AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthResponse.decode = function (reader, length, _end, _depth, _target) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $Reader.recursionLimit)
                        throw $Error("max depth exceeded");
                    var end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.extensions.api.cast_channel.AuthResponse();
                    while (reader.pos < end) {
                        var start = reader.pos;
                        var tag = reader.tag();
                        if (tag === _end) {
                            _end = $undefined;
                            break;
                        }
                        var wireType = tag & 7;
                        switch (tag >>>= 3) {
                        case 1: {
                                if (wireType !== 2)
                                    break;
                                message.signature = reader.bytes();
                                continue;
                            }
                        case 2: {
                                if (wireType !== 2)
                                    break;
                                message.clientAuthCertificate = reader.bytes();
                                continue;
                            }
                        case 3: {
                                if (wireType !== 2)
                                    break;
                                if (!(message.clientCa && message.clientCa.length))
                                    message.clientCa = [];
                                message.clientCa.push(reader.bytes());
                                continue;
                            }
                        }
                        reader.skipType(wireType, _depth, tag);
                        if (!reader.discardUnknown) {
                            $util.makeProp(message, "$unknowns", false);
                            (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                        }
                    }
                    if (_end !== $undefined)
                        throw $Error("missing end group");
                    if (!$Object.hasOwnProperty.call(message, "signature"))
                        throw $util.ProtocolError("missing required 'signature'", { instance: message });
                    if (!$Object.hasOwnProperty.call(message, "clientAuthCertificate"))
                        throw $util.ProtocolError("missing required 'clientAuthCertificate'", { instance: message });
                    return message;
                };

                /**
                 * Decodes an AuthResponse message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthResponse & extensions.api.cast_channel.AuthResponse.$Shape} AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthResponse.decodeDelimited = function(reader) {
                    if (!(reader instanceof $Reader))
                        reader = new $Reader(reader);
                    return this.decode(reader, reader.uint32());
                };

                /**
                 * Verifies an AuthResponse message.
                 * @function verify
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {Object.<string,*>} message Plain object to verify
                 * @returns {string|null} `null` if valid, otherwise the reason why it is not
                 */
                AuthResponse.verify = function (message, _depth) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        return "max depth exceeded";
                    if (!(message.signature && typeof message.signature.length === "number" || $util.isString(message.signature)))
                        return "signature: buffer expected";
                    if (!(message.clientAuthCertificate && typeof message.clientAuthCertificate.length === "number" || $util.isString(message.clientAuthCertificate)))
                        return "clientAuthCertificate: buffer expected";
                    if (message.clientCa != null && $Object.hasOwnProperty.call(message, "clientCa")) {
                        if (!$Array.isArray(message.clientCa))
                            return "clientCa: array expected";
                        for (var i = 0; i < message.clientCa.length; ++i)
                            if (!(message.clientCa[i] && typeof message.clientCa[i].length === "number" || $util.isString(message.clientCa[i])))
                                return "clientCa: buffer[] expected";
                    }
                    return null;
                };

                /**
                 * Creates an AuthResponse message from a plain object. Also converts values to their respective internal types.
                 * @function fromObject
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {Object.<string,*>} object Plain object
                 * @returns {extensions.api.cast_channel.AuthResponse} AuthResponse
                 */
                AuthResponse.fromObject = function (object, _depth) {
                    if (object instanceof $root.extensions.api.cast_channel.AuthResponse)
                        return object;
                    if (!$util.isObject(object))
                        throw $TypeError(".extensions.api.cast_channel.AuthResponse: object expected");
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var message = new $root.extensions.api.cast_channel.AuthResponse();
                    if (object.signature != null)
                        if (typeof object.signature === "string")
                            $util.base64.decode(object.signature, message.signature = $util.newBuffer($util.base64.length(object.signature)), 0);
                        else if (object.signature.length >= 0)
                            message.signature = object.signature;
                    if (object.clientAuthCertificate != null)
                        if (typeof object.clientAuthCertificate === "string")
                            $util.base64.decode(object.clientAuthCertificate, message.clientAuthCertificate = $util.newBuffer($util.base64.length(object.clientAuthCertificate)), 0);
                        else if (object.clientAuthCertificate.length >= 0)
                            message.clientAuthCertificate = object.clientAuthCertificate;
                    if (object.clientCa) {
                        if (!$Array.isArray(object.clientCa))
                            throw $TypeError(".extensions.api.cast_channel.AuthResponse.clientCa: array expected");
                        message.clientCa = $Array(object.clientCa.length);
                        for (var i = 0; i < object.clientCa.length; ++i)
                            if (typeof object.clientCa[i] === "string")
                                $util.base64.decode(object.clientCa[i], message.clientCa[i] = $util.newBuffer($util.base64.length(object.clientCa[i])), 0);
                            else if (object.clientCa[i].length >= 0)
                                message.clientCa[i] = object.clientCa[i];
                    }
                    return message;
                };

                /**
                 * Creates a plain object from an AuthResponse message. Also converts values to other types if specified.
                 * @function toObject
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {extensions.api.cast_channel.AuthResponse} message AuthResponse
                 * @param {$protobuf.IConversionOptions} [options] Conversion options
                 * @returns {Object.<string,*>} Plain object
                 */
                AuthResponse.toObject = function (message, options, _depth) {
                    if (!options)
                        options = {};
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var object = {};
                    if (options.arrays || options.defaults)
                        object.clientCa = [];
                    if (options.defaults) {
                        if (options.bytes === $String)
                            object.signature = "";
                        else {
                            object.signature = [];
                            if (options.bytes !== $Array)
                                object.signature = $util.newBuffer(object.signature);
                        }
                        if (options.bytes === $String)
                            object.clientAuthCertificate = "";
                        else {
                            object.clientAuthCertificate = [];
                            if (options.bytes !== $Array)
                                object.clientAuthCertificate = $util.newBuffer(object.clientAuthCertificate);
                        }
                    }
                    if (message.signature != null && $Object.hasOwnProperty.call(message, "signature"))
                        object.signature = options.bytes === $String ? $util.base64.encode(message.signature, 0, message.signature.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.signature) : message.signature;
                    if (message.clientAuthCertificate != null && $Object.hasOwnProperty.call(message, "clientAuthCertificate"))
                        object.clientAuthCertificate = options.bytes === $String ? $util.base64.encode(message.clientAuthCertificate, 0, message.clientAuthCertificate.length) : options.bytes === $Array ? $Array.prototype.slice.call(message.clientAuthCertificate) : message.clientAuthCertificate;
                    if (message.clientCa && message.clientCa.length) {
                        object.clientCa = $Array(message.clientCa.length);
                        for (var j = 0; j < message.clientCa.length; ++j)
                            object.clientCa[j] = options.bytes === $String ? $util.base64.encode(message.clientCa[j], 0, message.clientCa[j].length) : options.bytes === $Array ? $Array.prototype.slice.call(message.clientCa[j]) : message.clientCa[j];
                    }
                    return object;
                };

                /**
                 * Converts this AuthResponse to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                AuthResponse.prototype.toJSON = function() {
                    return AuthResponse.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the type url for AuthResponse
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns {string} The type url
                 */
                AuthResponse.getTypeUrl = function(prefix) {
                    if (prefix === $undefined)
                        prefix = "type.googleapis.com";
                    return prefix + "/extensions.api.cast_channel.AuthResponse";
                };

                return AuthResponse;
            })();

            cast_channel.AuthError = (function() {

                /**
                 * Properties of an AuthError.
                 * @typedef {Object} extensions.api.cast_channel.AuthError.$Properties
                 * @property {extensions.api.cast_channel.AuthError.ErrorType} errorType AuthError errorType
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */

                /**
                 * Properties of an AuthError.
                 * @memberof extensions.api.cast_channel
                 * @interface IAuthError
                 * @augments extensions.api.cast_channel.AuthError.$Properties
                 * @deprecated Use extensions.api.cast_channel.AuthError.$Properties instead.
                 */

                /**
                 * Shape of an AuthError.
                 * @typedef {extensions.api.cast_channel.AuthError.$Properties} extensions.api.cast_channel.AuthError.$Shape
                 */

                /**
                 * Constructs a new AuthError.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents an AuthError.
                 * @constructor
                 * @param {extensions.api.cast_channel.AuthError.$Properties=} [properties] Properties to set
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */
                var AuthError = function (properties) {
                    if (properties)
                        for (var keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null && keys[i] !== "__proto__")
                                this[keys[i]] = properties[keys[i]];
                };

                /**
                 * AuthError errorType.
                 * @member {extensions.api.cast_channel.AuthError.ErrorType} errorType
                 * @memberof extensions.api.cast_channel.AuthError
                 * @instance
                 */
                AuthError.prototype.errorType = 0;

                /**
                 * Creates a new AuthError instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {extensions.api.cast_channel.AuthError.$Properties=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.AuthError} AuthError instance
                 * @type {{
                 *   (properties: extensions.api.cast_channel.AuthError.$Shape): extensions.api.cast_channel.AuthError & extensions.api.cast_channel.AuthError.$Shape;
                 *   (properties?: extensions.api.cast_channel.AuthError.$Properties): extensions.api.cast_channel.AuthError;
                 * }}
                 */
                AuthError.create = function(properties) {
                    return new AuthError(properties);
                };

                /**
                 * Encodes the specified AuthError message. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {extensions.api.cast_channel.AuthError.$Properties} message AuthError message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthError.encode = function (message, writer, _depth) {
                    if (!writer)
                        writer = $Writer.create();
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    writer.uint32(/* id 1, wireType 0 =*/8).int32(message.errorType);
                    if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                        for (var i = 0; i < message.$unknowns.length; ++i)
                            writer.raw(message.$unknowns[i]);
                    return writer;
                };

                /**
                 * Encodes the specified AuthError message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {extensions.api.cast_channel.AuthError.$Properties} message AuthError message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthError.encodeDelimited = function(message, writer) {
                    return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
                };

                /**
                 * Decodes an AuthError message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthError & extensions.api.cast_channel.AuthError.$Shape} AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthError.decode = function (reader, length, _end, _depth, _target) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $Reader.recursionLimit)
                        throw $Error("max depth exceeded");
                    var end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.extensions.api.cast_channel.AuthError();
                    while (reader.pos < end) {
                        var start = reader.pos;
                        var tag = reader.tag();
                        if (tag === _end) {
                            _end = $undefined;
                            break;
                        }
                        var wireType = tag & 7;
                        switch (tag >>>= 3) {
                        case 1: {
                                if (wireType !== 0)
                                    break;
                                message.errorType = reader.int32();
                                continue;
                            }
                        }
                        reader.skipType(wireType, _depth, tag);
                        if (!reader.discardUnknown) {
                            $util.makeProp(message, "$unknowns", false);
                            (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                        }
                    }
                    if (_end !== $undefined)
                        throw $Error("missing end group");
                    if (!$Object.hasOwnProperty.call(message, "errorType"))
                        throw $util.ProtocolError("missing required 'errorType'", { instance: message });
                    return message;
                };

                /**
                 * Decodes an AuthError message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthError & extensions.api.cast_channel.AuthError.$Shape} AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthError.decodeDelimited = function(reader) {
                    if (!(reader instanceof $Reader))
                        reader = new $Reader(reader);
                    return this.decode(reader, reader.uint32());
                };

                /**
                 * Verifies an AuthError message.
                 * @function verify
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {Object.<string,*>} message Plain object to verify
                 * @returns {string|null} `null` if valid, otherwise the reason why it is not
                 */
                AuthError.verify = function (message, _depth) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        return "max depth exceeded";
                    switch (message.errorType) {
                    default:
                        return "errorType: enum value expected";
                    case 0:
                    case 1:
                        break;
                    }
                    return null;
                };

                /**
                 * Creates an AuthError message from a plain object. Also converts values to their respective internal types.
                 * @function fromObject
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {Object.<string,*>} object Plain object
                 * @returns {extensions.api.cast_channel.AuthError} AuthError
                 */
                AuthError.fromObject = function (object, _depth) {
                    if (object instanceof $root.extensions.api.cast_channel.AuthError)
                        return object;
                    if (!$util.isObject(object))
                        throw $TypeError(".extensions.api.cast_channel.AuthError: object expected");
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var message = new $root.extensions.api.cast_channel.AuthError();
                    switch (object.errorType) {
                    default:
                        if (typeof object.errorType === "number") {
                            message.errorType = object.errorType;
                            break;
                        }
                        break;
                    case "INTERNAL_ERROR":
                    case 0:
                        message.errorType = 0;
                        break;
                    case "NO_TLS":
                    case 1:
                        message.errorType = 1;
                        break;
                    }
                    return message;
                };

                /**
                 * Creates a plain object from an AuthError message. Also converts values to other types if specified.
                 * @function toObject
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {extensions.api.cast_channel.AuthError} message AuthError
                 * @param {$protobuf.IConversionOptions} [options] Conversion options
                 * @returns {Object.<string,*>} Plain object
                 */
                AuthError.toObject = function (message, options, _depth) {
                    if (!options)
                        options = {};
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var object = {};
                    if (options.defaults)
                        object.errorType = options.enums === $String ? "INTERNAL_ERROR" : 0;
                    if (message.errorType != null && $Object.hasOwnProperty.call(message, "errorType"))
                        object.errorType = options.enums === $String ? $root.extensions.api.cast_channel.AuthError.ErrorType[message.errorType] === $undefined ? message.errorType : $root.extensions.api.cast_channel.AuthError.ErrorType[message.errorType] : message.errorType;
                    return object;
                };

                /**
                 * Converts this AuthError to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.AuthError
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                AuthError.prototype.toJSON = function() {
                    return AuthError.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the type url for AuthError
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns {string} The type url
                 */
                AuthError.getTypeUrl = function(prefix) {
                    if (prefix === $undefined)
                        prefix = "type.googleapis.com";
                    return prefix + "/extensions.api.cast_channel.AuthError";
                };

                /**
                 * ErrorType enum.
                 * @name extensions.api.cast_channel.AuthError.ErrorType
                 * @enum {number}
                 * @property {number} INTERNAL_ERROR=0 INTERNAL_ERROR value
                 * @property {number} NO_TLS=1 NO_TLS value
                 */
                AuthError.ErrorType = (function() {
                    var valuesById = {}, values = $Object.create(valuesById);
                    values[valuesById[0] = "INTERNAL_ERROR"] = 0;
                    values[valuesById[1] = "NO_TLS"] = 1;
                    return values;
                })();

                return AuthError;
            })();

            cast_channel.DeviceAuthMessage = (function() {

                /**
                 * Properties of a DeviceAuthMessage.
                 * @typedef {Object} extensions.api.cast_channel.DeviceAuthMessage.$Properties
                 * @property {extensions.api.cast_channel.AuthChallenge.$Properties|null} [challenge] DeviceAuthMessage challenge
                 * @property {extensions.api.cast_channel.AuthResponse.$Properties|null} [response] DeviceAuthMessage response
                 * @property {extensions.api.cast_channel.AuthError.$Properties|null} [error] DeviceAuthMessage error
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */

                /**
                 * Properties of a DeviceAuthMessage.
                 * @memberof extensions.api.cast_channel
                 * @interface IDeviceAuthMessage
                 * @augments extensions.api.cast_channel.DeviceAuthMessage.$Properties
                 * @deprecated Use extensions.api.cast_channel.DeviceAuthMessage.$Properties instead.
                 */

                /**
                 * Shape of a DeviceAuthMessage.
                 * @typedef {extensions.api.cast_channel.DeviceAuthMessage.$Properties} extensions.api.cast_channel.DeviceAuthMessage.$Shape
                 */

                /**
                 * Constructs a new DeviceAuthMessage.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents a DeviceAuthMessage.
                 * @constructor
                 * @param {extensions.api.cast_channel.DeviceAuthMessage.$Properties=} [properties] Properties to set
                 * @property {Array.<Uint8Array>} [$unknowns] Unknown fields preserved while decoding when enabled
                 */
                var DeviceAuthMessage = function (properties) {
                    if (properties)
                        for (var keys = $Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null && keys[i] !== "__proto__")
                                this[keys[i]] = properties[keys[i]];
                };

                /**
                 * DeviceAuthMessage challenge.
                 * @member {extensions.api.cast_channel.AuthChallenge.$Properties|null|undefined} challenge
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 */
                DeviceAuthMessage.prototype.challenge = null;

                /**
                 * DeviceAuthMessage response.
                 * @member {extensions.api.cast_channel.AuthResponse.$Properties|null|undefined} response
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 */
                DeviceAuthMessage.prototype.response = null;

                /**
                 * DeviceAuthMessage error.
                 * @member {extensions.api.cast_channel.AuthError.$Properties|null|undefined} error
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 */
                DeviceAuthMessage.prototype.error = null;

                /**
                 * Creates a new DeviceAuthMessage instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.DeviceAuthMessage.$Properties=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage} DeviceAuthMessage instance
                 * @type {{
                 *   (properties: extensions.api.cast_channel.DeviceAuthMessage.$Shape): extensions.api.cast_channel.DeviceAuthMessage & extensions.api.cast_channel.DeviceAuthMessage.$Shape;
                 *   (properties?: extensions.api.cast_channel.DeviceAuthMessage.$Properties): extensions.api.cast_channel.DeviceAuthMessage;
                 * }}
                 */
                DeviceAuthMessage.create = function(properties) {
                    return new DeviceAuthMessage(properties);
                };

                /**
                 * Encodes the specified DeviceAuthMessage message. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.DeviceAuthMessage.$Properties} message DeviceAuthMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                DeviceAuthMessage.encode = function (message, writer, _depth) {
                    if (!writer)
                        writer = $Writer.create();
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    if (message.challenge != null && $Object.hasOwnProperty.call(message, "challenge"))
                        $root.extensions.api.cast_channel.AuthChallenge.encode(message.challenge, writer.uint32(/* id 1, wireType 2 =*/10).fork(), _depth + 1).ldelim();
                    if (message.response != null && $Object.hasOwnProperty.call(message, "response"))
                        $root.extensions.api.cast_channel.AuthResponse.encode(message.response, writer.uint32(/* id 2, wireType 2 =*/18).fork(), _depth + 1).ldelim();
                    if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
                        $root.extensions.api.cast_channel.AuthError.encode(message.error, writer.uint32(/* id 3, wireType 2 =*/26).fork(), _depth + 1).ldelim();
                    if (message.$unknowns != null && $Object.hasOwnProperty.call(message, "$unknowns"))
                        for (var i = 0; i < message.$unknowns.length; ++i)
                            writer.raw(message.$unknowns[i]);
                    return writer;
                };

                /**
                 * Encodes the specified DeviceAuthMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.DeviceAuthMessage.$Properties} message DeviceAuthMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                DeviceAuthMessage.encodeDelimited = function(message, writer) {
                    return this.encode(message, writer && writer.len ? writer.fork() : writer).ldelim();
                };

                /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage & extensions.api.cast_channel.DeviceAuthMessage.$Shape} DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                DeviceAuthMessage.decode = function (reader, length, _end, _depth, _target) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $Reader.recursionLimit)
                        throw $Error("max depth exceeded");
                    var end = length === $undefined ? reader.len : reader.pos + length, message = _target || new $root.extensions.api.cast_channel.DeviceAuthMessage();
                    while (reader.pos < end) {
                        var start = reader.pos;
                        var tag = reader.tag();
                        if (tag === _end) {
                            _end = $undefined;
                            break;
                        }
                        var wireType = tag & 7;
                        switch (tag >>>= 3) {
                        case 1: {
                                if (wireType !== 2)
                                    break;
                                message.challenge = $root.extensions.api.cast_channel.AuthChallenge.decode(reader, reader.uint32(), $undefined, _depth + 1, message.challenge);
                                continue;
                            }
                        case 2: {
                                if (wireType !== 2)
                                    break;
                                message.response = $root.extensions.api.cast_channel.AuthResponse.decode(reader, reader.uint32(), $undefined, _depth + 1, message.response);
                                continue;
                            }
                        case 3: {
                                if (wireType !== 2)
                                    break;
                                message.error = $root.extensions.api.cast_channel.AuthError.decode(reader, reader.uint32(), $undefined, _depth + 1, message.error);
                                continue;
                            }
                        }
                        reader.skipType(wireType, _depth, tag);
                        if (!reader.discardUnknown) {
                            $util.makeProp(message, "$unknowns", false);
                            (message.$unknowns || (message.$unknowns = [])).push(reader.raw(start, reader.pos));
                        }
                    }
                    if (_end !== $undefined)
                        throw $Error("missing end group");
                    return message;
                };

                /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage & extensions.api.cast_channel.DeviceAuthMessage.$Shape} DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                DeviceAuthMessage.decodeDelimited = function(reader) {
                    if (!(reader instanceof $Reader))
                        reader = new $Reader(reader);
                    return this.decode(reader, reader.uint32());
                };

                /**
                 * Verifies a DeviceAuthMessage message.
                 * @function verify
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {Object.<string,*>} message Plain object to verify
                 * @returns {string|null} `null` if valid, otherwise the reason why it is not
                 */
                DeviceAuthMessage.verify = function (message, _depth) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        return "max depth exceeded";
                    if (message.challenge != null && $Object.hasOwnProperty.call(message, "challenge")) {
                        var error = $root.extensions.api.cast_channel.AuthChallenge.verify(message.challenge, _depth + 1);
                        if (error)
                            return "challenge." + error;
                    }
                    if (message.response != null && $Object.hasOwnProperty.call(message, "response")) {
                        var error = $root.extensions.api.cast_channel.AuthResponse.verify(message.response, _depth + 1);
                        if (error)
                            return "response." + error;
                    }
                    if (message.error != null && $Object.hasOwnProperty.call(message, "error")) {
                        var error = $root.extensions.api.cast_channel.AuthError.verify(message.error, _depth + 1);
                        if (error)
                            return "error." + error;
                    }
                    return null;
                };

                /**
                 * Creates a DeviceAuthMessage message from a plain object. Also converts values to their respective internal types.
                 * @function fromObject
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {Object.<string,*>} object Plain object
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage} DeviceAuthMessage
                 */
                DeviceAuthMessage.fromObject = function (object, _depth) {
                    if (object instanceof $root.extensions.api.cast_channel.DeviceAuthMessage)
                        return object;
                    if (!$util.isObject(object))
                        throw $TypeError(".extensions.api.cast_channel.DeviceAuthMessage: object expected");
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var message = new $root.extensions.api.cast_channel.DeviceAuthMessage();
                    if (object.challenge != null) {
                        if (!$util.isObject(object.challenge))
                            throw $TypeError(".extensions.api.cast_channel.DeviceAuthMessage.challenge: object expected");
                        message.challenge = $root.extensions.api.cast_channel.AuthChallenge.fromObject(object.challenge, _depth + 1);
                    }
                    if (object.response != null) {
                        if (!$util.isObject(object.response))
                            throw $TypeError(".extensions.api.cast_channel.DeviceAuthMessage.response: object expected");
                        message.response = $root.extensions.api.cast_channel.AuthResponse.fromObject(object.response, _depth + 1);
                    }
                    if (object.error != null) {
                        if (!$util.isObject(object.error))
                            throw $TypeError(".extensions.api.cast_channel.DeviceAuthMessage.error: object expected");
                        message.error = $root.extensions.api.cast_channel.AuthError.fromObject(object.error, _depth + 1);
                    }
                    return message;
                };

                /**
                 * Creates a plain object from a DeviceAuthMessage message. Also converts values to other types if specified.
                 * @function toObject
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.DeviceAuthMessage} message DeviceAuthMessage
                 * @param {$protobuf.IConversionOptions} [options] Conversion options
                 * @returns {Object.<string,*>} Plain object
                 */
                DeviceAuthMessage.toObject = function (message, options, _depth) {
                    if (!options)
                        options = {};
                    if (_depth === $undefined)
                        _depth = 0;
                    if (_depth > $util.recursionLimit)
                        throw $Error("max depth exceeded");
                    var object = {};
                    if (options.defaults) {
                        object.challenge = null;
                        object.response = null;
                        object.error = null;
                    }
                    if (message.challenge != null && $Object.hasOwnProperty.call(message, "challenge"))
                        object.challenge = $root.extensions.api.cast_channel.AuthChallenge.toObject(message.challenge, options, _depth + 1);
                    if (message.response != null && $Object.hasOwnProperty.call(message, "response"))
                        object.response = $root.extensions.api.cast_channel.AuthResponse.toObject(message.response, options, _depth + 1);
                    if (message.error != null && $Object.hasOwnProperty.call(message, "error"))
                        object.error = $root.extensions.api.cast_channel.AuthError.toObject(message.error, options, _depth + 1);
                    return object;
                };

                /**
                 * Converts this DeviceAuthMessage to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                DeviceAuthMessage.prototype.toJSON = function() {
                    return DeviceAuthMessage.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the type url for DeviceAuthMessage
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {string} [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns {string} The type url
                 */
                DeviceAuthMessage.getTypeUrl = function(prefix) {
                    if (prefix === $undefined)
                        prefix = "type.googleapis.com";
                    return prefix + "/extensions.api.cast_channel.DeviceAuthMessage";
                };

                return DeviceAuthMessage;
            })();

            return cast_channel;
        })();

        return api;
    })();

    return extensions;
})();

module.exports = $root;
