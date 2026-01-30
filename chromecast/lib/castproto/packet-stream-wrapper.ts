import { EventEmitter } from 'node:events'

import type { TLSSocket } from 'node:tls'

const WAITING_HEADER = 0
const WAITING_PACKET = 1

export default class PacketStreamWrapper extends EventEmitter {
  stream
  constructor (stream: TLSSocket) {
    super()

    this.stream = stream

    let state = WAITING_HEADER
    let packetLength = 0

    this.stream.on('readable', () => {
      while (true) {
        switch (state) {
          case WAITING_HEADER: {
            const header = stream.read(4)
            if (header === null) return
            packetLength = header.readUInt32BE(0)
            state = WAITING_PACKET
            break
          }
          case WAITING_PACKET: {
            const packet = stream.read(packetLength)
            if (packet === null) return
            this.emit('packet', packet)
            state = WAITING_HEADER
            break
          }
        }
      }
    })
  }

  send (buf: Uint8Array) {
    const header = Buffer.allocUnsafe(4)
    header.writeUInt32BE(buf.length, 0)
    this.stream.write(Buffer.concat([header, buf]))
  }
}
