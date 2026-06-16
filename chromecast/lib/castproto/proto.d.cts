/* eslint-disable @typescript-eslint/no-explicit-any */
import type * as $protobuf from 'protobufjs'

/** Namespace extensions. */
export namespace extensions {

    /** Namespace api. */
    namespace api {

        /** Namespace cast_channel. */
        namespace cast_channel {

            /**
             * Properties of a CastMessage.
             * @deprecated Use extensions.api.cast_channel.CastMessage.$Properties instead.
             */
            interface ICastMessage extends CastMessage.$Properties {
            }

            /** Represents a CastMessage. */
            class CastMessage {
              /**
                 * Constructs a new CastMessage.
                 * @param [properties] Properties to set
                 */
              constructor(properties?: CastMessage.$Properties)

              /** Unknown fields preserved while decoding when enabled */
              $unknowns?: Uint8Array[]

              /** CastMessage protocolVersion. */
              protocolVersion: CastMessage.ProtocolVersion

              /** CastMessage sourceId. */
              sourceId: string

              /** CastMessage destinationId. */
              destinationId: string

              /** CastMessage namespace. */
              namespace: string

              /** CastMessage payloadType. */
              payloadType: CastMessage.PayloadType

              /** CastMessage payloadUtf8. */
              payloadUtf8: string

              /** CastMessage payloadBinary. */
              payloadBinary: Uint8Array

              /**
                 * Creates a new CastMessage instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns CastMessage instance
                 */
              static create(properties: CastMessage.$Shape): CastMessage & CastMessage.$Shape
              static create(properties?: CastMessage.$Properties): CastMessage

              /**
                 * Encodes the specified CastMessage message. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @param message CastMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encode(message: CastMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Encodes the specified CastMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.CastMessage.verify|verify} messages.
                 * @param message CastMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encodeDelimited(message: CastMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Decodes a CastMessage message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.CastMessage & extensions.api.cast_channel.CastMessage.$Shape} CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): CastMessage & CastMessage.$Shape

              /**
                 * Decodes a CastMessage message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.CastMessage & extensions.api.cast_channel.CastMessage.$Shape} CastMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): CastMessage & CastMessage.$Shape

              /**
                 * Verifies a CastMessage message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
              static verify(message: Record<string, any>): (string|null)

              /**
                 * Creates a CastMessage message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns CastMessage
                 */
              static fromObject(object: Record<string, any>): CastMessage

              /**
                 * Creates a plain object from a CastMessage message. Also converts values to other types if specified.
                 * @param message CastMessage
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
              static toObject(message: CastMessage, options?: $protobuf.IConversionOptions): Record<string, any>

              /**
                 * Converts this CastMessage to JSON.
                 * @returns JSON object
                 */
              toJSON(): Record<string, any>

              /**
                 * Gets the type url for CastMessage
                 * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns The type url
                 */
              static getTypeUrl(prefix?: string): string
            }

            namespace CastMessage {

                /** Properties of a CastMessage. */
                interface $Properties {

                    /** CastMessage protocolVersion */
                    protocolVersion: ProtocolVersion

                    /** CastMessage sourceId */
                    sourceId: string

                    /** CastMessage destinationId */
                    destinationId: string

                    /** CastMessage namespace */
                    namespace: string

                    /** CastMessage payloadType */
                    payloadType: PayloadType

                    /** CastMessage payloadUtf8 */
                    payloadUtf8?: (string|null)

                    /** CastMessage payloadBinary */
                    payloadBinary?: (Uint8Array|null)

                    /** Unknown fields preserved while decoding when enabled */
                    $unknowns?: Uint8Array[]
                }

                /** Shape of a CastMessage. */
                type $Shape = $Properties

                /** ProtocolVersion enum. */
                enum ProtocolVersion {

                    /** CASTV2_1_0 value */
                    CASTV2_1_0 = 0
                }

                /** PayloadType enum. */
                enum PayloadType {

                    /** STRING value */
                    STRING = 0,

                    /** BINARY value */
                    BINARY = 1
                }
            }

            /**
             * Properties of an AuthChallenge.
             * @deprecated Use extensions.api.cast_channel.AuthChallenge.$Properties instead.
             */
            interface IAuthChallenge extends AuthChallenge.$Properties {
            }

            /** Represents an AuthChallenge. */
            class AuthChallenge {
              /**
                 * Constructs a new AuthChallenge.
                 * @param [properties] Properties to set
                 */
              constructor(properties?: AuthChallenge.$Properties)

              /** Unknown fields preserved while decoding when enabled */
              $unknowns?: Uint8Array[]

              /**
                 * Creates a new AuthChallenge instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns AuthChallenge instance
                 */
              static create(properties: AuthChallenge.$Shape): AuthChallenge & AuthChallenge.$Shape
              static create(properties?: AuthChallenge.$Properties): AuthChallenge

              /**
                 * Encodes the specified AuthChallenge message. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @param message AuthChallenge message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encode(message: AuthChallenge.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Encodes the specified AuthChallenge message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthChallenge.verify|verify} messages.
                 * @param message AuthChallenge message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encodeDelimited(message: AuthChallenge.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Decodes an AuthChallenge message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthChallenge & extensions.api.cast_channel.AuthChallenge.$Shape} AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): AuthChallenge & AuthChallenge.$Shape

              /**
                 * Decodes an AuthChallenge message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthChallenge & extensions.api.cast_channel.AuthChallenge.$Shape} AuthChallenge
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): AuthChallenge & AuthChallenge.$Shape

              /**
                 * Verifies an AuthChallenge message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
              static verify(message: Record<string, any>): (string|null)

              /**
                 * Creates an AuthChallenge message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns AuthChallenge
                 */
              static fromObject(object: Record<string, any>): AuthChallenge

              /**
                 * Creates a plain object from an AuthChallenge message. Also converts values to other types if specified.
                 * @param message AuthChallenge
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
              static toObject(message: AuthChallenge, options?: $protobuf.IConversionOptions): Record<string, any>

              /**
                 * Converts this AuthChallenge to JSON.
                 * @returns JSON object
                 */
              toJSON(): Record<string, any>

              /**
                 * Gets the type url for AuthChallenge
                 * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns The type url
                 */
              static getTypeUrl(prefix?: string): string
            }

            namespace AuthChallenge {

                /** Properties of an AuthChallenge. */
                interface $Properties {

                    /** Unknown fields preserved while decoding when enabled */
                    $unknowns?: Uint8Array[]
                }

                /** Shape of an AuthChallenge. */
                type $Shape = $Properties
            }

            /**
             * Properties of an AuthResponse.
             * @deprecated Use extensions.api.cast_channel.AuthResponse.$Properties instead.
             */
            interface IAuthResponse extends AuthResponse.$Properties {
            }

            /** Represents an AuthResponse. */
            class AuthResponse {
              /**
                 * Constructs a new AuthResponse.
                 * @param [properties] Properties to set
                 */
              constructor(properties?: AuthResponse.$Properties)

              /** Unknown fields preserved while decoding when enabled */
              $unknowns?: Uint8Array[]

              /** AuthResponse signature. */
              signature: Uint8Array

              /** AuthResponse clientAuthCertificate. */
              clientAuthCertificate: Uint8Array

              /** AuthResponse clientCa. */
              clientCa: Uint8Array[]

              /**
                 * Creates a new AuthResponse instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns AuthResponse instance
                 */
              static create(properties: AuthResponse.$Shape): AuthResponse & AuthResponse.$Shape
              static create(properties?: AuthResponse.$Properties): AuthResponse

              /**
                 * Encodes the specified AuthResponse message. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @param message AuthResponse message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encode(message: AuthResponse.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Encodes the specified AuthResponse message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthResponse.verify|verify} messages.
                 * @param message AuthResponse message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encodeDelimited(message: AuthResponse.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Decodes an AuthResponse message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthResponse & extensions.api.cast_channel.AuthResponse.$Shape} AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): AuthResponse & AuthResponse.$Shape

              /**
                 * Decodes an AuthResponse message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthResponse & extensions.api.cast_channel.AuthResponse.$Shape} AuthResponse
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): AuthResponse & AuthResponse.$Shape

              /**
                 * Verifies an AuthResponse message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
              static verify(message: Record<string, any>): (string|null)

              /**
                 * Creates an AuthResponse message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns AuthResponse
                 */
              static fromObject(object: Record<string, any>): AuthResponse

              /**
                 * Creates a plain object from an AuthResponse message. Also converts values to other types if specified.
                 * @param message AuthResponse
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
              static toObject(message: AuthResponse, options?: $protobuf.IConversionOptions): Record<string, any>

              /**
                 * Converts this AuthResponse to JSON.
                 * @returns JSON object
                 */
              toJSON(): Record<string, any>

              /**
                 * Gets the type url for AuthResponse
                 * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns The type url
                 */
              static getTypeUrl(prefix?: string): string
            }

            namespace AuthResponse {

                /** Properties of an AuthResponse. */
                interface $Properties {

                    /** AuthResponse signature */
                    signature: Uint8Array

                    /** AuthResponse clientAuthCertificate */
                    clientAuthCertificate: Uint8Array

                    /** AuthResponse clientCa */
                    clientCa?: (Uint8Array[]|null)

                    /** Unknown fields preserved while decoding when enabled */
                    $unknowns?: Uint8Array[]
                }

                /** Shape of an AuthResponse. */
                type $Shape = $Properties
            }

            /**
             * Properties of an AuthError.
             * @deprecated Use extensions.api.cast_channel.AuthError.$Properties instead.
             */
            interface IAuthError extends AuthError.$Properties {
            }

            /** Represents an AuthError. */
            class AuthError {
              /**
                 * Constructs a new AuthError.
                 * @param [properties] Properties to set
                 */
              constructor(properties?: AuthError.$Properties)

              /** Unknown fields preserved while decoding when enabled */
              $unknowns?: Uint8Array[]

              /** AuthError errorType. */
              errorType: AuthError.ErrorType

              /**
                 * Creates a new AuthError instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns AuthError instance
                 */
              static create(properties: AuthError.$Shape): AuthError & AuthError.$Shape
              static create(properties?: AuthError.$Properties): AuthError

              /**
                 * Encodes the specified AuthError message. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @param message AuthError message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encode(message: AuthError.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Encodes the specified AuthError message, length delimited. Does not implicitly {@link extensions.api.cast_channel.AuthError.verify|verify} messages.
                 * @param message AuthError message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encodeDelimited(message: AuthError.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Decodes an AuthError message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.AuthError & extensions.api.cast_channel.AuthError.$Shape} AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): AuthError & AuthError.$Shape

              /**
                 * Decodes an AuthError message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.AuthError & extensions.api.cast_channel.AuthError.$Shape} AuthError
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): AuthError & AuthError.$Shape

              /**
                 * Verifies an AuthError message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
              static verify(message: Record<string, any>): (string|null)

              /**
                 * Creates an AuthError message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns AuthError
                 */
              static fromObject(object: Record<string, any>): AuthError

              /**
                 * Creates a plain object from an AuthError message. Also converts values to other types if specified.
                 * @param message AuthError
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
              static toObject(message: AuthError, options?: $protobuf.IConversionOptions): Record<string, any>

              /**
                 * Converts this AuthError to JSON.
                 * @returns JSON object
                 */
              toJSON(): Record<string, any>

              /**
                 * Gets the type url for AuthError
                 * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns The type url
                 */
              static getTypeUrl(prefix?: string): string
            }

            namespace AuthError {

                /** Properties of an AuthError. */
                interface $Properties {

                    /** AuthError errorType */
                    errorType: ErrorType

                    /** Unknown fields preserved while decoding when enabled */
                    $unknowns?: Uint8Array[]
                }

                /** Shape of an AuthError. */
                type $Shape = $Properties

                /** ErrorType enum. */
                enum ErrorType {

                    /** INTERNAL_ERROR value */
                    INTERNAL_ERROR = 0,

                    /** NO_TLS value */
                    NO_TLS = 1
                }
            }

            /**
             * Properties of a DeviceAuthMessage.
             * @deprecated Use extensions.api.cast_channel.DeviceAuthMessage.$Properties instead.
             */
            interface IDeviceAuthMessage extends DeviceAuthMessage.$Properties {
            }

            /** Represents a DeviceAuthMessage. */
            class DeviceAuthMessage {
              /**
                 * Constructs a new DeviceAuthMessage.
                 * @param [properties] Properties to set
                 */
              constructor(properties?: DeviceAuthMessage.$Properties)

              /** Unknown fields preserved while decoding when enabled */
              $unknowns?: Uint8Array[]

              /** DeviceAuthMessage challenge. */
              challenge?: (AuthChallenge.$Properties|null)

              /** DeviceAuthMessage response. */
              response?: (AuthResponse.$Properties|null)

              /** DeviceAuthMessage error. */
              error?: (AuthError.$Properties|null)

              /**
                 * Creates a new DeviceAuthMessage instance using the specified properties.
                 * @param [properties] Properties to set
                 * @returns DeviceAuthMessage instance
                 */
              static create(properties: DeviceAuthMessage.$Shape): DeviceAuthMessage & DeviceAuthMessage.$Shape
              static create(properties?: DeviceAuthMessage.$Properties): DeviceAuthMessage

              /**
                 * Encodes the specified DeviceAuthMessage message. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @param message DeviceAuthMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encode(message: DeviceAuthMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Encodes the specified DeviceAuthMessage message, length delimited. Does not implicitly {@link extensions.api.cast_channel.DeviceAuthMessage.verify|verify} messages.
                 * @param message DeviceAuthMessage message or plain object to encode
                 * @param [writer] Writer to encode to
                 * @returns Writer
                 */
              static encodeDelimited(message: DeviceAuthMessage.$Properties, writer?: $protobuf.Writer): $protobuf.Writer

              /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer.
                 * @param reader Reader or buffer to decode from
                 * @param [length] Message length if known beforehand
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage & extensions.api.cast_channel.DeviceAuthMessage.$Shape} DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): DeviceAuthMessage & DeviceAuthMessage.$Shape

              /**
                 * Decodes a DeviceAuthMessage message from the specified reader or buffer, length delimited.
                 * @param reader Reader or buffer to decode from
                 * @returns {extensions.api.cast_channel.DeviceAuthMessage & extensions.api.cast_channel.DeviceAuthMessage.$Shape} DeviceAuthMessage
                 * @throws {Error} If the payload is not a reader or valid buffer
                 * @throws {$protobuf.util.ProtocolError} If required fields are missing
                 */
              static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): DeviceAuthMessage & DeviceAuthMessage.$Shape

              /**
                 * Verifies a DeviceAuthMessage message.
                 * @param message Plain object to verify
                 * @returns `null` if valid, otherwise the reason why it is not
                 */
              static verify(message: Record<string, any>): (string|null)

              /**
                 * Creates a DeviceAuthMessage message from a plain object. Also converts values to their respective internal types.
                 * @param object Plain object
                 * @returns DeviceAuthMessage
                 */
              static fromObject(object: Record<string, any>): DeviceAuthMessage

              /**
                 * Creates a plain object from a DeviceAuthMessage message. Also converts values to other types if specified.
                 * @param message DeviceAuthMessage
                 * @param [options] Conversion options
                 * @returns Plain object
                 */
              static toObject(message: DeviceAuthMessage, options?: $protobuf.IConversionOptions): Record<string, any>

              /**
                 * Converts this DeviceAuthMessage to JSON.
                 * @returns JSON object
                 */
              toJSON(): Record<string, any>

              /**
                 * Gets the type url for DeviceAuthMessage
                 * @param [prefix] Custom type url prefix, defaults to `"type.googleapis.com"`
                 * @returns The type url
                 */
              static getTypeUrl(prefix?: string): string
            }

            namespace DeviceAuthMessage {

                /** Properties of a DeviceAuthMessage. */
                interface $Properties {

                    /** DeviceAuthMessage challenge */
                    challenge?: (AuthChallenge.$Properties|null)

                    /** DeviceAuthMessage response */
                    response?: (AuthResponse.$Properties|null)

                    /** DeviceAuthMessage error */
                    error?: (AuthError.$Properties|null)

                    /** Unknown fields preserved while decoding when enabled */
                    $unknowns?: Uint8Array[]
                }

                /** Shape of a DeviceAuthMessage. */
                type $Shape = $Properties
            }
        }
    }
}
