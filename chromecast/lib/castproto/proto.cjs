/*eslint-disable block-scoped-var, id-length, no-control-regex, no-magic-numbers, no-prototype-builtins, no-redeclare, no-shadow, no-var, sort-vars*/
"use strict";

var $protobuf = require("protobufjs/minimal");

// Common aliases
var $Reader = $protobuf.Reader, $Writer = $protobuf.Writer, $util = $protobuf.util;

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
                 * @memberof extensions.api.cast_channel
                 * @interface ICastMessage
                 * @property {extensions.api.cast_channel.CastMessage.ProtocolVersion} protocolVersion CastMessage protocolVersion
                 * @property {string} sourceId CastMessage sourceId
                 * @property {string} destinationId CastMessage destinationId
                 * @property {string} namespace CastMessage namespace
                 * @property {extensions.api.cast_channel.CastMessage.PayloadType} payloadType CastMessage payloadType
                 * @property {string|null} [payloadUtf8] CastMessage payloadUtf8
                 * @property {Uint8Array|null} [payloadBinary] CastMessage payloadBinary
                 */

                /**
                 * Constructs a new CastMessage.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents a CastMessage.
                 * @implements ICastMessage
                 * @constructor
                 * @param {extensions.api.cast_channel.ICastMessage=} [properties] Properties to set
                 */
                function CastMessage(properties) {
                    if (properties)
                        for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null)
                                this[keys[i]] = properties[keys[i]];
                }

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
                 * @param {extensions.api.cast_channel.ICastMessage=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.CastMessage} CastMessage instance
                 */
                CastMessage.create = function create(properties) {
                    return new CastMessage(properties);
                };

                /**
                 * Encodes the specified CastMessage message. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {extensions.api.cast_channel.ICastMessage} message CastMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                CastMessage.encode = function encode(message, writer) {
                    if (!writer)
                        writer = $Writer.create();
                    writer.uint32(/* id 1, wireType 0 =*/8).int32(message.protocolVersion);
                    writer.uint32(/* id 2, wireType 2 =*/18).string(message.sourceId);
                    writer.uint32(/* id 3, wireType 2 =*/26).string(message.destinationId);
                    writer.uint32(/* id 4, wireType 2 =*/34).string(message.namespace);
                    writer.uint32(/* id 5, wireType 0 =*/40).int32(message.payloadType);
                    if (message.payloadUtf8 != null && Object.hasOwnProperty.call(message, "payloadUtf8"))
                        writer.uint32(/* id 6, wireType 2 =*/50).string(message.payloadUtf8);
                    if (message.payloadBinary != null && Object.hasOwnProperty.call(message, "payloadBinary"))
                        writer.uint32(/* id 7, wireType 2 =*/58).bytes(message.payloadBinary);
                    return writer;
                };

                /**
                 * Encodes the specified CastMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {extensions.api.cast_channel.ICastMessage} message CastMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                CastMessage.encodeDelimited = function encodeDelimited(message, writer) {
                    return this.encode(message, writer).ldelim();
                };

                /**
                 * Decodes a CastMessage message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.CastMessage} CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                CastMessage.decode = function decode(reader, length, error) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    var end = length === undefined ? reader.len : reader.pos + length, message = new $root.extensions.api.cast_channel.CastMessage();
                    while (reader.pos < end) {
                        var tag = reader.uint32();
                        if (tag === error)
                            break;
                        switch (tag >>> 3) {
                        case 1: {
                                message.protocolVersion = reader.int32();
                                break;
                            }
                        case 2: {
                                message.sourceId = reader.string();
                                break;
                            }
                        case 3: {
                                message.destinationId = reader.string();
                                break;
                            }
                        case 4: {
                                message.namespace = reader.string();
                                break;
                            }
                        case 5: {
                                message.payloadType = reader.int32();
                                break;
                            }
                        case 6: {
                                message.payloadUtf8 = reader.string();
                                break;
                            }
                        case 7: {
                                message.payloadBinary = reader.bytes();
                                break;
                            }
                        default:
                            reader.skipType(tag & 7);
                            break;
                        }
                    }
                    if (!message.hasOwnProperty("protocolVersion"))
                        throw $util.ProtocolError("missing required 'protocolVersion'", { instance: message });
                    if (!message.hasOwnProperty("sourceId"))
                        throw $util.ProtocolError("missing required 'sourceId'", { instance: message });
                    if (!message.hasOwnProperty("destinationId"))
                        throw $util.ProtocolError("missing required 'destinationId'", { instance: message });
                    if (!message.hasOwnProperty("namespace"))
                        throw $util.ProtocolError("missing required 'namespace'", { instance: message });
                    if (!message.hasOwnProperty("payloadType"))
                        throw $util.ProtocolError("missing required 'payloadType'", { instance: message });
                    return message;
                };

                /**
                 * Decodes a CastMessage message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.CastMessage} CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                CastMessage.decodeDelimited = function decodeDelimited(reader) {
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
                CastMessage.verify = function verify(message) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
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
                    if (message.payloadUtf8 != null && message.hasOwnProperty("payloadUtf8"))
                        if (!$util.isString(message.payloadUtf8))
                            return "payloadUtf8: string expected";
                    if (message.payloadBinary != null && message.hasOwnProperty("payloadBinary"))
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
                CastMessage.fromObject = function fromObject(object) {
                    if (object instanceof $root.extensions.api.cast_channel.CastMessage)
                        return object;
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
                        message.sourceId = String(object.sourceId);
                    if (object.destinationId != null)
                        message.destinationId = String(object.destinationId);
                    if (object.namespace != null)
                        message.namespace = String(object.namespace);
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
                        message.payloadUtf8 = String(object.payloadUtf8);
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
                CastMessage.toObject = function toObject(message, options) {
                    if (!options)
                        options = {};
                    var object = {};
                    if (options.defaults) {
                        object.protocolVersion = options.enums === String ? "CASTV2_1_0" : 0;
                        object.sourceId = "";
                        object.destinationId = "";
                        object.namespace = "";
                        object.payloadType = options.enums === String ? "STRING" : 0;
                        object.payloadUtf8 = "";
                        if (options.bytes === String)
                            object.payloadBinary = "";
                        else {
                            object.payloadBinary = [];
                            if (options.bytes !== Array)
                                object.payloadBinary = $util.newBuffer(object.payloadBinary);
                        }
                    }
                    if (message.protocolVersion != null && message.hasOwnProperty("protocolVersion"))
                        object.protocolVersion = options.enums === String ? $root.extensions.api.cast_channel.CastMessage.ProtocolVersion[message.protocolVersion] === undefined ? message.protocolVersion : $root.extensions.api.cast_channel.CastMessage.ProtocolVersion[message.protocolVersion] : message.protocolVersion;
                    if (message.sourceId != null && message.hasOwnProperty("sourceId"))
                        object.sourceId = message.sourceId;
                    if (message.destinationId != null && message.hasOwnProperty("destinationId"))
                        object.destinationId = message.destinationId;
                    if (message.namespace != null && message.hasOwnProperty("namespace"))
                        object.namespace = message.namespace;
                    if (message.payloadType != null && message.hasOwnProperty("payloadType"))
                        object.payloadType = options.enums === String ? $root.extensions.api.cast_channel.CastMessage.PayloadType[message.payloadType] === undefined ? message.payloadType : $root.extensions.api.cast_channel.CastMessage.PayloadType[message.payloadType] : message.payloadType;
                    if (message.payloadUtf8 != null && message.hasOwnProperty("payloadUtf8"))
                        object.payloadUtf8 = message.payloadUtf8;
                    if (message.payloadBinary != null && message.hasOwnProperty("payloadBinary"))
                        object.payloadBinary = options.bytes === String ? $util.base64.encode(message.payloadBinary, 0, message.payloadBinary.length) : options.bytes === Array ? Array.prototype.slice.call(message.payloadBinary) : message.payloadBinary;
                    return object;
                };

                /**
                 * Converts this CastMessage to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                CastMessage.prototype.toJSON = function toJSON() {
                    return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the default type url for CastMessage
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.CastMessage
                 * @static
                 * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns {string} The default type url
                 */
                CastMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                    if (typeUrlPrefix === undefined) {
                        typeUrlPrefix = "type.googleapis.com";
                    }
                    return typeUrlPrefix + "/extensions.api.cast_channel.CastMessage";
                };

                /**
                 * ProtocolVersion enum.
                 * @name extensions.api.cast_channel.CastMessage.ProtocolVersion
                 * @enum {number}
                 * @property {number} CASTV2_1_0=0 CASTV2_1_0 value
                 */
                CastMessage.ProtocolVersion = (function() {
                    var valuesById = {}, values = Object.create(valuesById);
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
                    var valuesById = {}, values = Object.create(valuesById);
                    values[valuesById[0] = "STRING"] = 0;
                    values[valuesById[1] = "BINARY"] = 1;
                    return values;
                })();

                return CastMessage;
            })();

            cast_channel.AuthChallenge = (function() {

                /**
                 * Properties of an AuthChallenge.
                 * @memberof extensions.api.cast_channel
                 * @interface IAuthChallenge
                 */

                /**
                 * Constructs a new AuthChallenge.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents an AuthChallenge.
                 * @implements IAuthChallenge
                 * @constructor
                 * @param {extensions.api.cast_channel.IAuthChallenge=} [properties] Properties to set
                 */
                function AuthChallenge(properties) {
                    if (properties)
                        for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null)
                                this[keys[i]] = properties[keys[i]];
                }

                /**
                 * Creates a new AuthChallenge instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.IAuthChallenge=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.AuthChallenge} AuthChallenge instance
                 */
                AuthChallenge.create = function create(properties) {
                    return new AuthChallenge(properties);
                };

                /**
                 * Encodes the specified AuthChallenge message. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.IAuthChallenge} message AuthChallenge message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthChallenge.encode = function encode(message, writer) {
                    if (!writer)
                        writer = $Writer.create();
                    return writer;
                };

                /**
                 * Encodes the specified AuthChallenge message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {extensions.api.cast_channel.IAuthChallenge} message AuthChallenge message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthChallenge.encodeDelimited = function encodeDelimited(message, writer) {
                    return this.encode(message, writer).ldelim();
                };

                /**
                 * Decodes an AuthChallenge message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthChallenge} AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthChallenge.decode = function decode(reader, length, error) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    var end = length === undefined ? reader.len : reader.pos + length, message = new $root.extensions.api.cast_channel.AuthChallenge();
                    while (reader.pos < end) {
                        var tag = reader.uint32();
                        if (tag === error)
                            break;
                        switch (tag >>> 3) {
                        default:
                            reader.skipType(tag & 7);
                            break;
                        }
                    }
                    return message;
                };

                /**
                 * Decodes an AuthChallenge message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthChallenge} AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthChallenge.decodeDelimited = function decodeDelimited(reader) {
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
                AuthChallenge.verify = function verify(message) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
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
                AuthChallenge.fromObject = function fromObject(object) {
                    if (object instanceof $root.extensions.api.cast_channel.AuthChallenge)
                        return object;
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
                AuthChallenge.toObject = function toObject() {
                    return {};
                };

                /**
                 * Converts this AuthChallenge to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                AuthChallenge.prototype.toJSON = function toJSON() {
                    return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the default type url for AuthChallenge
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.AuthChallenge
                 * @static
                 * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns {string} The default type url
                 */
                AuthChallenge.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                    if (typeUrlPrefix === undefined) {
                        typeUrlPrefix = "type.googleapis.com";
                    }
                    return typeUrlPrefix + "/extensions.api.cast_channel.AuthChallenge";
                };

                return AuthChallenge;
            })();

            cast_channel.AuthResponse = (function() {

                /**
                 * Properties of an AuthResponse.
                 * @memberof extensions.api.cast_channel
                 * @interface IAuthResponse
                 * @property {Uint8Array} signature AuthResponse signature
                 * @property {Uint8Array} clientAuthCertificate AuthResponse clientAuthCertificate
                 * @property {Array.<Uint8Array>|null} [clientCa] AuthResponse clientCa
                 */

                /**
                 * Constructs a new AuthResponse.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents an AuthResponse.
                 * @implements IAuthResponse
                 * @constructor
                 * @param {extensions.api.cast_channel.IAuthResponse=} [properties] Properties to set
                 */
                function AuthResponse(properties) {
                    this.clientCa = [];
                    if (properties)
                        for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null)
                                this[keys[i]] = properties[keys[i]];
                }

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
                 * @param {extensions.api.cast_channel.IAuthResponse=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.AuthResponse} AuthResponse instance
                 */
                AuthResponse.create = function create(properties) {
                    return new AuthResponse(properties);
                };

                /**
                 * Encodes the specified AuthResponse message. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {extensions.api.cast_channel.IAuthResponse} message AuthResponse message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthResponse.encode = function encode(message, writer) {
                    if (!writer)
                        writer = $Writer.create();
                    writer.uint32(/* id 1, wireType 2 =*/10).bytes(message.signature);
                    writer.uint32(/* id 2, wireType 2 =*/18).bytes(message.clientAuthCertificate);
                    if (message.clientCa != null && message.clientCa.length)
                        for (var i = 0; i < message.clientCa.length; ++i)
                            writer.uint32(/* id 3, wireType 2 =*/26).bytes(message.clientCa[i]);
                    return writer;
                };

                /**
                 * Encodes the specified AuthResponse message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {extensions.api.cast_channel.IAuthResponse} message AuthResponse message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthResponse.encodeDelimited = function encodeDelimited(message, writer) {
                    return this.encode(message, writer).ldelim();
                };

                /**
                 * Decodes an AuthResponse message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthResponse} AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthResponse.decode = function decode(reader, length, error) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    var end = length === undefined ? reader.len : reader.pos + length, message = new $root.extensions.api.cast_channel.AuthResponse();
                    while (reader.pos < end) {
                        var tag = reader.uint32();
                        if (tag === error)
                            break;
                        switch (tag >>> 3) {
                        case 1: {
                                message.signature = reader.bytes();
                                break;
                            }
                        case 2: {
                                message.clientAuthCertificate = reader.bytes();
                                break;
                            }
                        case 3: {
                                if (!(message.clientCa && message.clientCa.length))
                                    message.clientCa = [];
                                message.clientCa.push(reader.bytes());
                                break;
                            }
                        default:
                            reader.skipType(tag & 7);
                            break;
                        }
                    }
                    if (!message.hasOwnProperty("signature"))
                        throw $util.ProtocolError("missing required 'signature'", { instance: message });
                    if (!message.hasOwnProperty("clientAuthCertificate"))
                        throw $util.ProtocolError("missing required 'clientAuthCertificate'", { instance: message });
                    return message;
                };

                /**
                 * Decodes an AuthResponse message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthResponse} AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthResponse.decodeDelimited = function decodeDelimited(reader) {
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
                AuthResponse.verify = function verify(message) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (!(message.signature && typeof message.signature.length === "number" || $util.isString(message.signature)))
                        return "signature: buffer expected";
                    if (!(message.clientAuthCertificate && typeof message.clientAuthCertificate.length === "number" || $util.isString(message.clientAuthCertificate)))
                        return "clientAuthCertificate: buffer expected";
                    if (message.clientCa != null && message.hasOwnProperty("clientCa")) {
                        if (!Array.isArray(message.clientCa))
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
                AuthResponse.fromObject = function fromObject(object) {
                    if (object instanceof $root.extensions.api.cast_channel.AuthResponse)
                        return object;
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
                        if (!Array.isArray(object.clientCa))
                            throw TypeError(".extensions.api.cast_channel.AuthResponse.clientCa: array expected");
                        message.clientCa = [];
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
                AuthResponse.toObject = function toObject(message, options) {
                    if (!options)
                        options = {};
                    var object = {};
                    if (options.arrays || options.defaults)
                        object.clientCa = [];
                    if (options.defaults) {
                        if (options.bytes === String)
                            object.signature = "";
                        else {
                            object.signature = [];
                            if (options.bytes !== Array)
                                object.signature = $util.newBuffer(object.signature);
                        }
                        if (options.bytes === String)
                            object.clientAuthCertificate = "";
                        else {
                            object.clientAuthCertificate = [];
                            if (options.bytes !== Array)
                                object.clientAuthCertificate = $util.newBuffer(object.clientAuthCertificate);
                        }
                    }
                    if (message.signature != null && message.hasOwnProperty("signature"))
                        object.signature = options.bytes === String ? $util.base64.encode(message.signature, 0, message.signature.length) : options.bytes === Array ? Array.prototype.slice.call(message.signature) : message.signature;
                    if (message.clientAuthCertificate != null && message.hasOwnProperty("clientAuthCertificate"))
                        object.clientAuthCertificate = options.bytes === String ? $util.base64.encode(message.clientAuthCertificate, 0, message.clientAuthCertificate.length) : options.bytes === Array ? Array.prototype.slice.call(message.clientAuthCertificate) : message.clientAuthCertificate;
                    if (message.clientCa && message.clientCa.length) {
                        object.clientCa = [];
                        for (var j = 0; j < message.clientCa.length; ++j)
                            object.clientCa[j] = options.bytes === String ? $util.base64.encode(message.clientCa[j], 0, message.clientCa[j].length) : options.bytes === Array ? Array.prototype.slice.call(message.clientCa[j]) : message.clientCa[j];
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
                AuthResponse.prototype.toJSON = function toJSON() {
                    return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the default type url for AuthResponse
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.AuthResponse
                 * @static
                 * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns {string} The default type url
                 */
                AuthResponse.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                    if (typeUrlPrefix === undefined) {
                        typeUrlPrefix = "type.googleapis.com";
                    }
                    return typeUrlPrefix + "/extensions.api.cast_channel.AuthResponse";
                };

                return AuthResponse;
            })();

            cast_channel.AuthError = (function() {

                /**
                 * Properties of an AuthError.
                 * @memberof extensions.api.cast_channel
                 * @interface IAuthError
                 * @property {extensions.api.cast_channel.AuthError.ErrorType} errorType AuthError errorType
                 */

                /**
                 * Constructs a new AuthError.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents an AuthError.
                 * @implements IAuthError
                 * @constructor
                 * @param {extensions.api.cast_channel.IAuthError=} [properties] Properties to set
                 */
                function AuthError(properties) {
                    if (properties)
                        for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null)
                                this[keys[i]] = properties[keys[i]];
                }

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
                 * @param {extensions.api.cast_channel.IAuthError=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.AuthError} AuthError instance
                 */
                AuthError.create = function create(properties) {
                    return new AuthError(properties);
                };

                /**
                 * Encodes the specified AuthError message. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {extensions.api.cast_channel.IAuthError} message AuthError message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthError.encode = function encode(message, writer) {
                    if (!writer)
                        writer = $Writer.create();
                    writer.uint32(/* id 1, wireType 0 =*/8).int32(message.errorType);
                    return writer;
                };

                /**
                 * Encodes the specified AuthError message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {extensions.api.cast_channel.IAuthError} message AuthError message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                AuthError.encodeDelimited = function encodeDelimited(message, writer) {
                    return this.encode(message, writer).ldelim();
                };

                /**
                 * Decodes an AuthError message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthError} AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthError.decode = function decode(reader, length, error) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    var end = length === undefined ? reader.len : reader.pos + length, message = new $root.extensions.api.cast_channel.AuthError();
                    while (reader.pos < end) {
                        var tag = reader.uint32();
                        if (tag === error)
                            break;
                        switch (tag >>> 3) {
                        case 1: {
                                message.errorType = reader.int32();
                                break;
                            }
                        default:
                            reader.skipType(tag & 7);
                            break;
                        }
                    }
                    if (!message.hasOwnProperty("errorType"))
                        throw $util.ProtocolError("missing required 'errorType'", { instance: message });
                    return message;
                };

                /**
                 * Decodes an AuthError message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthError} AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                AuthError.decodeDelimited = function decodeDelimited(reader) {
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
                AuthError.verify = function verify(message) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
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
                AuthError.fromObject = function fromObject(object) {
                    if (object instanceof $root.extensions.api.cast_channel.AuthError)
                        return object;
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
                AuthError.toObject = function toObject(message, options) {
                    if (!options)
                        options = {};
                    var object = {};
                    if (options.defaults)
                        object.errorType = options.enums === String ? "INTERNAL_ERROR" : 0;
                    if (message.errorType != null && message.hasOwnProperty("errorType"))
                        object.errorType = options.enums === String ? $root.extensions.api.cast_channel.AuthError.ErrorType[message.errorType] === undefined ? message.errorType : $root.extensions.api.cast_channel.AuthError.ErrorType[message.errorType] : message.errorType;
                    return object;
                };

                /**
                 * Converts this AuthError to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.AuthError
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                AuthError.prototype.toJSON = function toJSON() {
                    return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the default type url for AuthError
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.AuthError
                 * @static
                 * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns {string} The default type url
                 */
                AuthError.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                    if (typeUrlPrefix === undefined) {
                        typeUrlPrefix = "type.googleapis.com";
                    }
                    return typeUrlPrefix + "/extensions.api.cast_channel.AuthError";
                };

                /**
                 * ErrorType enum.
                 * @name extensions.api.cast_channel.AuthError.ErrorType
                 * @enum {number}
                 * @property {number} INTERNAL_ERROR=0 INTERNAL_ERROR value
                 * @property {number} NO_TLS=1 NO_TLS value
                 */
                AuthError.ErrorType = (function() {
                    var valuesById = {}, values = Object.create(valuesById);
                    values[valuesById[0] = "INTERNAL_ERROR"] = 0;
                    values[valuesById[1] = "NO_TLS"] = 1;
                    return values;
                })();

                return AuthError;
            })();

            cast_channel.DeviceAuthMessage = (function() {

                /**
                 * Properties of a DeviceAuthMessage.
                 * @memberof extensions.api.cast_channel
                 * @interface IDeviceAuthMessage
                 * @property {extensions.api.cast_channel.IAuthChallenge|null} [challenge] DeviceAuthMessage challenge
                 * @property {extensions.api.cast_channel.IAuthResponse|null} [response] DeviceAuthMessage response
                 * @property {extensions.api.cast_channel.IAuthError|null} [error] DeviceAuthMessage error
                 */

                /**
                 * Constructs a new DeviceAuthMessage.
                 * @memberof extensions.api.cast_channel
                 * @classdesc Represents a DeviceAuthMessage.
                 * @implements IDeviceAuthMessage
                 * @constructor
                 * @param {extensions.api.cast_channel.IDeviceAuthMessage=} [properties] Properties to set
                 */
                function DeviceAuthMessage(properties) {
                    if (properties)
                        for (var keys = Object.keys(properties), i = 0; i < keys.length; ++i)
                            if (properties[keys[i]] != null)
                                this[keys[i]] = properties[keys[i]];
                }

                /**
                 * DeviceAuthMessage challenge.
                 * @member {extensions.api.cast_channel.IAuthChallenge|null|undefined} challenge
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 */
                DeviceAuthMessage.prototype.challenge = null;

                /**
                 * DeviceAuthMessage response.
                 * @member {extensions.api.cast_channel.IAuthResponse|null|undefined} response
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 */
                DeviceAuthMessage.prototype.response = null;

                /**
                 * DeviceAuthMessage error.
                 * @member {extensions.api.cast_channel.IAuthError|null|undefined} error
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 */
                DeviceAuthMessage.prototype.error = null;

                /**
                 * Creates a new DeviceAuthMessage instance using the specified properties.
                 * @function create
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.IDeviceAuthMessage=} [properties] Properties to set
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage} DeviceAuthMessage instance
                 */
                DeviceAuthMessage.create = function create(properties) {
                    return new DeviceAuthMessage(properties);
                };

                /**
                 * Encodes the specified DeviceAuthMessage message. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @function encode
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.IDeviceAuthMessage} message DeviceAuthMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                DeviceAuthMessage.encode = function encode(message, writer) {
                    if (!writer)
                        writer = $Writer.create();
                    if (message.challenge != null && Object.hasOwnProperty.call(message, "challenge"))
                        $root.extensions.api.cast_channel.AuthChallenge.encode(message.challenge, writer.uint32(/* id 1, wireType 2 =*/10).fork()).ldelim();
                    if (message.response != null && Object.hasOwnProperty.call(message, "response"))
                        $root.extensions.api.cast_channel.AuthResponse.encode(message.response, writer.uint32(/* id 2, wireType 2 =*/18).fork()).ldelim();
                    if (message.error != null && Object.hasOwnProperty.call(message, "error"))
                        $root.extensions.api.cast_channel.AuthError.encode(message.error, writer.uint32(/* id 3, wireType 2 =*/26).fork()).ldelim();
                    return writer;
                };

                /**
                 * Encodes the specified DeviceAuthMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @function encodeDelimited
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {extensions.api.cast_channel.IDeviceAuthMessage} message DeviceAuthMessage message or plain object to encode
                 * @param {$protobuf.Writer} [writer] Writer to encode to
                 * @returns {$protobuf.Writer} Writer
                 */
                DeviceAuthMessage.encodeDelimited = function encodeDelimited(message, writer) {
                    return this.encode(message, writer).ldelim();
                };

                /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer.
                 * @function decode
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @param {number} [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage} DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                DeviceAuthMessage.decode = function decode(reader, length, error) {
                    if (!(reader instanceof $Reader))
                        reader = $Reader.create(reader);
                    var end = length === undefined ? reader.len : reader.pos + length, message = new $root.extensions.api.cast_channel.DeviceAuthMessage();
                    while (reader.pos < end) {
                        var tag = reader.uint32();
                        if (tag === error)
                            break;
                        switch (tag >>> 3) {
                        case 1: {
                                message.challenge = $root.extensions.api.cast_channel.AuthChallenge.decode(reader, reader.uint32());
                                break;
                            }
                        case 2: {
                                message.response = $root.extensions.api.cast_channel.AuthResponse.decode(reader, reader.uint32());
                                break;
                            }
                        case 3: {
                                message.error = $root.extensions.api.cast_channel.AuthError.decode(reader, reader.uint32());
                                break;
                            }
                        default:
                            reader.skipType(tag & 7);
                            break;
                        }
                    }
                    return message;
                };

                /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer, length delimited.
                 * @function decodeDelimited
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {$protobuf.Reader|Uint8Array} reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage} DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                DeviceAuthMessage.decodeDelimited = function decodeDelimited(reader) {
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
                DeviceAuthMessage.verify = function verify(message) {
                    if (typeof message !== "object" || message === null)
                        return "object expected";
                    if (message.challenge != null && message.hasOwnProperty("challenge")) {
                        var error = $root.extensions.api.cast_channel.AuthChallenge.verify(message.challenge);
                        if (error)
                            return "challenge." + error;
                    }
                    if (message.response != null && message.hasOwnProperty("response")) {
                        var error = $root.extensions.api.cast_channel.AuthResponse.verify(message.response);
                        if (error)
                            return "response." + error;
                    }
                    if (message.error != null && message.hasOwnProperty("error")) {
                        var error = $root.extensions.api.cast_channel.AuthError.verify(message.error);
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
                DeviceAuthMessage.fromObject = function fromObject(object) {
                    if (object instanceof $root.extensions.api.cast_channel.DeviceAuthMessage)
                        return object;
                    var message = new $root.extensions.api.cast_channel.DeviceAuthMessage();
                    if (object.challenge != null) {
                        if (typeof object.challenge !== "object")
                            throw TypeError(".extensions.api.cast_channel.DeviceAuthMessage.challenge: object expected");
                        message.challenge = $root.extensions.api.cast_channel.AuthChallenge.fromObject(object.challenge);
                    }
                    if (object.response != null) {
                        if (typeof object.response !== "object")
                            throw TypeError(".extensions.api.cast_channel.DeviceAuthMessage.response: object expected");
                        message.response = $root.extensions.api.cast_channel.AuthResponse.fromObject(object.response);
                    }
                    if (object.error != null) {
                        if (typeof object.error !== "object")
                            throw TypeError(".extensions.api.cast_channel.DeviceAuthMessage.error: object expected");
                        message.error = $root.extensions.api.cast_channel.AuthError.fromObject(object.error);
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
                DeviceAuthMessage.toObject = function toObject(message, options) {
                    if (!options)
                        options = {};
                    var object = {};
                    if (options.defaults) {
                        object.challenge = null;
                        object.response = null;
                        object.error = null;
                    }
                    if (message.challenge != null && message.hasOwnProperty("challenge"))
                        object.challenge = $root.extensions.api.cast_channel.AuthChallenge.toObject(message.challenge, options);
                    if (message.response != null && message.hasOwnProperty("response"))
                        object.response = $root.extensions.api.cast_channel.AuthResponse.toObject(message.response, options);
                    if (message.error != null && message.hasOwnProperty("error"))
                        object.error = $root.extensions.api.cast_channel.AuthError.toObject(message.error, options);
                    return object;
                };

                /**
                 * Converts this DeviceAuthMessage to JSON.
                 * @function toJSON
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @instance
                 * @returns {Object.<string,*>} JSON object
                 */
                DeviceAuthMessage.prototype.toJSON = function toJSON() {
                    return this.constructor.toObject(this, $protobuf.util.toJSONOptions);
                };

                /**
                 * Gets the default type url for DeviceAuthMessage
                 * @function getTypeUrl
                 * @memberof extensions.api.cast_channel.DeviceAuthMessage
                 * @static
                 * @param {string} [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns {string} The default type url
                 */
                DeviceAuthMessage.getTypeUrl = function getTypeUrl(typeUrlPrefix) {
                    if (typeUrlPrefix === undefined) {
                        typeUrlPrefix = "type.googleapis.com";
                    }
                    return typeUrlPrefix + "/extensions.api.cast_channel.DeviceAuthMessage";
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
