import EventEmitter from 'node:events'
import tls from 'node:tls'

import Debug from 'debug'

import Channel from './channel.ts'
import PacketStreamWrapper from './packet-stream-wrapper.ts'
import proto from './proto.cjs'

const debug = Debug('castv2')

const CastMessage = proto.extensions.api.cast_channel.CastMessage

export interface ApplicationInfo {
  appId: string
  appType: string
  displayName: string
  iconUrl: string
  isIdleScreen: boolean
  launchedFromCloud: boolean
  namespaces: ApplicationNamespace[]
  sessionId: string
  statusText: string
  transportId: string
  universalAppId: string
}

export interface ApplicationNamespace {
  name: string
}

export class Client extends EventEmitter {
  socket: tls.TLSSocket | null = null
  ps: PacketStreamWrapper | null = null

  connect (options: tls.ConnectionOptions | string, callback?: () => void) {
    if (typeof options === 'string') {
      options = {
        host: options
      }
    }

    options.port = options.port ?? 8009
    options.rejectUnauthorized = false

    if (callback) this.once('connect', callback)

    debug('connecting to %s:%d ...', options.host, options.port)

    this.socket = tls.connect(options, () => {
      this.ps = new PacketStreamWrapper(this.socket!)
      this.ps.on('packet', onpacket)

      debug('connected')
      this.emit('connect')
    })

    const onerror = (err: Error) => {
      debug('error: %s %j', err.message, err)
      this.emit('error', err)
    }

    const onclose = () => {
      debug('connection closed')
      this.socket?.removeListener('error', onerror)
      this.socket = null
      if (this.ps) {
        this.ps.removeListener('packet', onpacket)
        this.ps = null
      }
      this.emit('close')
    }

    const onpacket = (buf: Buffer) => {
      const message = CastMessage.decode(buf)

      debug(
        'recv message: protocolVersion=%s sourceId=%s destinationId=%s namespace=%s data=%s',
        message.protocolVersion,
        message.sourceId,
        message.destinationId,
        message.namespace
      )

      if (message.protocolVersion !== 0) { // CASTV2_1_0
        this.emit('error', new Error('Unsupported protocol version: ' + message.protocolVersion))
        this.close()
        return
      }

      this.emit('message',
        message.sourceId,
        message.destinationId,
        message.namespace,
        (message.payloadType === 1) // BINARY
          ? message.payloadBinary
          : message.payloadUtf8
      )
    }

    this.socket.on('error', onerror)
    this.socket.once('close', onclose)
  }

  close () {
    debug('closing connection ...')
    // using socket.destroy here because socket.end caused stalled connection
    // in case of dongles going brutally down without a chance to FIN/ACK
    this.socket?.destroy()
  }

  send (sourceId: string, destinationId: string, namespace: string, data: any) {
    const message = {
      protocolVersion: 0, // CASTV2_1_0
      sourceId,
      destinationId,
      namespace,
      payloadType: 0 // STRING
    }

    if (Buffer.isBuffer(data)) {
      message.payloadType = 1 // BINARY;
      message.payloadBinary = data
    } else {
      message.payloadType = 0 // STRING;
      message.payloadUtf8 = data
    }

    debug(
      'send message: protocolVersion=%s sourceId=%s destinationId=%s namespace=%s data=%s',
      message.protocolVersion,
      message.sourceId,
      message.destinationId,
      message.namespace
    )

    this.ps?.send(CastMessage.encode(message).finish())
  }

  createChannel (sourceId: string, destinationId: string, namespace: string, encoding?: string) {
    return new Channel(this, sourceId, destinationId, namespace, encoding)
  }
}
