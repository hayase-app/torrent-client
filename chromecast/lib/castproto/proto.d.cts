import * as $protobuf from "protobufjs";
import Long = require("long");
/** Namespace extensions. */
export namespace extensions {

    /** Namespace api. */
    namespace api {

        /** Namespace cast_channel. */
        namespace cast_channel {

            /** Properties of a CastMessage. */
            interface ICastMessage {

                /** CastMessage protocolVersion */
                protocolVersion: extensions.api.cast_channel.CastMessage.ProtocolVersion;

                /** CastMessage sourceId */
                sourceId: string;

                /** CastMessage destinationId */
                destinationId: string;

                /** CastMessage namespace */
                namespace: string;

                /** CastMessage payloadType */
                payloadType: extensions.api.cast_channel.CastMessage.PayloadType;

                /** CastMessage payloadUtf8 */
                payloadUtf8?: (string|null);

                /** CastMessage payloadBinary */
                payloadBinary?: (Uint8Array|null);
            }

            /** Represents a CastMessage. */
            class CastMessage implements ICastMessage {

                /**
                 * Constructs a new CastMessage.
                 * @param [properties] Properties to set
                 */
                constructor(properties?: extensions.api.cast_channel.ICastMessage);

                /** CastMessage protocolVersion. */
                public protocolVersion: extensions.api.cast_channel.CastMessage.ProtocolVersion;

                /** CastMessage sourceId. */
                public sourceId: string;

                /** CastMessage destinationId. */
                public destinationId: string;

                /** CastMessage namespace. */
                public namespace: string;

                /** CastMessage payloadType. */
                public payloadType: extensions.api.cast_channel.CastMessage.PayloadType;

                /** CastMessage payloadUtf8. */
                public payloadUtf8: string;

                /** CastMessage payloadBinary. */
                public payloadBinary: Uint8Array;

                /**
                 * Creates a new CastMessage instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns CastMessage instance
                 */
                public static create(properties?: extensions.api.cast_channel.ICastMessage): extensions.api.cast_channel.CastMessage;

                /**
                 * Encodes the specified CastMessage message. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @param message CastMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encode(message: extensions.api.cast_channel.ICastMessage, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Encodes the specified CastMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @param message CastMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encodeDelimited(message: extensions.api.cast_channel.ICastMessage, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Decodes a CastMessage message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): extensions.api.cast_channel.CastMessage;

                /**
                 * Decodes a CastMessage message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): extensions.api.cast_channel.CastMessage;

                /**
                 * Verifies a CastMessage message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
                public static verify(message: { [k: string]: any }): (string|null);

                /**
                 * Creates a CastMessage message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns CastMessage
                 */
                public static fromObject(object: { [k: string]: any }): extensions.api.cast_channel.CastMessage;

                /**
                 * Creates a plain object from a CastMessage message. Also converts values to other types if specified.
                 * @param message CastMessage
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
                public static toObject(message: extensions.api.cast_channel.CastMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

                /**
                 * Converts this CastMessage to JSON.
                 * @returns JSON object
                 */
                public toJSON(): { [k: string]: any };

                /**
                 * Gets the default type url for CastMessage
                 * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns The default type url
                 */
                public static getTypeUrl(typeUrlPrefix?: string): string;
            }

            namespace CastMessage {

                /** ProtocolVersion enum. */
                enum ProtocolVersion {
                    CASTV2_1_0 = 0
                }

                /** PayloadType enum. */
                enum PayloadType {
                    STRING = 0,
                    BINARY = 1
                }
            }

            /** Properties of an AuthChallenge. */
            interface IAuthChallenge {
            }

            /** Represents an AuthChallenge. */
            class AuthChallenge implements IAuthChallenge {

                /**
                 * Constructs a new AuthChallenge.
                 * @param [properties] Properties to set
                 */
                constructor(properties?: extensions.api.cast_channel.IAuthChallenge);

                /**
                 * Creates a new AuthChallenge instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns AuthChallenge instance
                 */
                public static create(properties?: extensions.api.cast_channel.IAuthChallenge): extensions.api.cast_channel.AuthChallenge;

                /**
                 * Encodes the specified AuthChallenge message. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @param message AuthChallenge message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encode(message: extensions.api.cast_channel.IAuthChallenge, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Encodes the specified AuthChallenge message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @param message AuthChallenge message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encodeDelimited(message: extensions.api.cast_channel.IAuthChallenge, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Decodes an AuthChallenge message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): extensions.api.cast_channel.AuthChallenge;

                /**
                 * Decodes an AuthChallenge message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): extensions.api.cast_channel.AuthChallenge;

                /**
                 * Verifies an AuthChallenge message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
                public static verify(message: { [k: string]: any }): (string|null);

                /**
                 * Creates an AuthChallenge message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns AuthChallenge
                 */
                public static fromObject(object: { [k: string]: any }): extensions.api.cast_channel.AuthChallenge;

                /**
                 * Creates a plain object from an AuthChallenge message. Also converts values to other types if specified.
                 * @param message AuthChallenge
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
                public static toObject(message: extensions.api.cast_channel.AuthChallenge, options?: $protobuf.IConversionOptions): { [k: string]: any };

                /**
                 * Converts this AuthChallenge to JSON.
                 * @returns JSON object
                 */
                public toJSON(): { [k: string]: any };

                /**
                 * Gets the default type url for AuthChallenge
                 * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns The default type url
                 */
                public static getTypeUrl(typeUrlPrefix?: string): string;
            }

            /** Properties of an AuthResponse. */
            interface IAuthResponse {

                /** AuthResponse signature */
                signature: Uint8Array;

                /** AuthResponse clientAuthCertificate */
                clientAuthCertificate: Uint8Array;

                /** AuthResponse clientCa */
                clientCa?: (Uint8Array[]|null);
            }

            /** Represents an AuthResponse. */
            class AuthResponse implements IAuthResponse {

                /**
                 * Constructs a new AuthResponse.
                 * @param [properties] Properties to set
                 */
                constructor(properties?: extensions.api.cast_channel.IAuthResponse);

                /** AuthResponse signature. */
                public signature: Uint8Array;

                /** AuthResponse clientAuthCertificate. */
                public clientAuthCertificate: Uint8Array;

                /** AuthResponse clientCa. */
                public clientCa: Uint8Array[];

                /**
                 * Creates a new AuthResponse instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns AuthResponse instance
                 */
                public static create(properties?: extensions.api.cast_channel.IAuthResponse): extensions.api.cast_channel.AuthResponse;

                /**
                 * Encodes the specified AuthResponse message. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @param message AuthResponse message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encode(message: extensions.api.cast_channel.IAuthResponse, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Encodes the specified AuthResponse message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @param message AuthResponse message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encodeDelimited(message: extensions.api.cast_channel.IAuthResponse, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Decodes an AuthResponse message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): extensions.api.cast_channel.AuthResponse;

                /**
                 * Decodes an AuthResponse message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): extensions.api.cast_channel.AuthResponse;

                /**
                 * Verifies an AuthResponse message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
                public static verify(message: { [k: string]: any }): (string|null);

                /**
                 * Creates an AuthResponse message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns AuthResponse
                 */
                public static fromObject(object: { [k: string]: any }): extensions.api.cast_channel.AuthResponse;

                /**
                 * Creates a plain object from an AuthResponse message. Also converts values to other types if specified.
                 * @param message AuthResponse
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
                public static toObject(message: extensions.api.cast_channel.AuthResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

                /**
                 * Converts this AuthResponse to JSON.
                 * @returns JSON object
                 */
                public toJSON(): { [k: string]: any };

                /**
                 * Gets the default type url for AuthResponse
                 * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns The default type url
                 */
                public static getTypeUrl(typeUrlPrefix?: string): string;
            }

            /** Properties of an AuthError. */
            interface IAuthError {

                /** AuthError errorType */
                errorType: extensions.api.cast_channel.AuthError.ErrorType;
            }

            /** Represents an AuthError. */
            class AuthError implements IAuthError {

                /**
                 * Constructs a new AuthError.
                 * @param [properties] Properties to set
                 */
                constructor(properties?: extensions.api.cast_channel.IAuthError);

                /** AuthError errorType. */
                public errorType: extensions.api.cast_channel.AuthError.ErrorType;

                /**
                 * Creates a new AuthError instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns AuthError instance
                 */
                public static create(properties?: extensions.api.cast_channel.IAuthError): extensions.api.cast_channel.AuthError;

                /**
                 * Encodes the specified AuthError message. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @param message AuthError message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encode(message: extensions.api.cast_channel.IAuthError, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Encodes the specified AuthError message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @param message AuthError message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encodeDelimited(message: extensions.api.cast_channel.IAuthError, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Decodes an AuthError message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): extensions.api.cast_channel.AuthError;

                /**
                 * Decodes an AuthError message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): extensions.api.cast_channel.AuthError;

                /**
                 * Verifies an AuthError message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
                public static verify(message: { [k: string]: any }): (string|null);

                /**
                 * Creates an AuthError message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns AuthError
                 */
                public static fromObject(object: { [k: string]: any }): extensions.api.cast_channel.AuthError;

                /**
                 * Creates a plain object from an AuthError message. Also converts values to other types if specified.
                 * @param message AuthError
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
                public static toObject(message: extensions.api.cast_channel.AuthError, options?: $protobuf.IConversionOptions): { [k: string]: any };

                /**
                 * Converts this AuthError to JSON.
                 * @returns JSON object
                 */
                public toJSON(): { [k: string]: any };

                /**
                 * Gets the default type url for AuthError
                 * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns The default type url
                 */
                public static getTypeUrl(typeUrlPrefix?: string): string;
            }

            namespace AuthError {

                /** ErrorType enum. */
                enum ErrorType {
                    INTERNAL_ERROR = 0,
                    NO_TLS = 1
                }
            }

            /** Properties of a DeviceAuthMessage. */
            interface IDeviceAuthMessage {

                /** DeviceAuthMessage challenge */
                challenge?: (extensions.api.cast_channel.IAuthChallenge|null);

                /** DeviceAuthMessage response */
                response?: (extensions.api.cast_channel.IAuthResponse|null);

                /** DeviceAuthMessage error */
                error?: (extensions.api.cast_channel.IAuthError|null);
            }

            /** Represents a DeviceAuthMessage. */
            class DeviceAuthMessage implements IDeviceAuthMessage {

                /**
                 * Constructs a new DeviceAuthMessage.
                 * @param [properties] Properties to set
                 */
                constructor(properties?: extensions.api.cast_channel.IDeviceAuthMessage);

                /** DeviceAuthMessage challenge. */
                public challenge?: (extensions.api.cast_channel.IAuthChallenge|null);

                /** DeviceAuthMessage response. */
                public response?: (extensions.api.cast_channel.IAuthResponse|null);

                /** DeviceAuthMessage error. */
                public error?: (extensions.api.cast_channel.IAuthError|null);

                /**
                 * Creates a new DeviceAuthMessage instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns DeviceAuthMessage instance
                 */
                public static create(properties?: extensions.api.cast_channel.IDeviceAuthMessage): extensions.api.cast_channel.DeviceAuthMessage;

                /**
                 * Encodes the specified DeviceAuthMessage message. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @param message DeviceAuthMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encode(message: extensions.api.cast_channel.IDeviceAuthMessage, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Encodes the specified DeviceAuthMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @param message DeviceAuthMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
                public static encodeDelimited(message: extensions.api.cast_channel.IDeviceAuthMessage, writer?: $protobuf.Writer): $protobuf.Writer;

                /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): extensions.api.cast_channel.DeviceAuthMessage;

                /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
                public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): extensions.api.cast_channel.DeviceAuthMessage;

                /**
                 * Verifies a DeviceAuthMessage message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
                public static verify(message: { [k: string]: any }): (string|null);

                /**
                 * Creates a DeviceAuthMessage message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns DeviceAuthMessage
                 */
                public static fromObject(object: { [k: string]: any }): extensions.api.cast_channel.DeviceAuthMessage;

                /**
                 * Creates a plain object from a DeviceAuthMessage message. Also converts values to other types if specified.
                 * @param message DeviceAuthMessage
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
                public static toObject(message: extensions.api.cast_channel.DeviceAuthMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

                /**
                 * Converts this DeviceAuthMessage to JSON.
                 * @returns JSON object
                 */
                public toJSON(): { [k: string]: any };

                /**
                 * Gets the default type url for DeviceAuthMessage
                 * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
                 * @returns The default type url
                 */
                public static getTypeUrl(typeUrlPrefix?: string): string;
            }
        }
    }
}
