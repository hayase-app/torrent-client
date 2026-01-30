/* eslint-disable @typescript-eslint/no-explicit-any */
import { EventEmitter } from 'node:events'

import type { Client } from './client.ts'

export default class Channel extends EventEmitter {
  bus
  sourceId
  destinationId
  namespace
  encoding
  constructor (bus: Client, sourceId: string, destinationId: string, namespace: string, encoding?: string) {
    super()

    this.bus = bus
    this.sourceId = sourceId
    this.destinationId = destinationId
    this.namespace = namespace
    this.encoding = encoding

    const onmessage = (sourceId: string, destinationId: string, namespace: string, data: any) => {
      if (sourceId !== this.destinationId) return
      if (destinationId !== this.sourceId && destinationId !== '*') return
      if (namespace !== this.namespace) return
      this.emit('message', decode(data, this.encoding), destinationId === '*')
    }

    const onclose = () => {
      this.bus.removeListener('message', onmessage)
    }

    this.bus.on('message', onmessage)
    this.once('close', onclose)
  }

  send (data: any) {
    this.bus.send(
      this.sourceId,
      this.destinationId,
      this.namespace,
      encode(data, this.encoding)
    )
  }

  close () {
    this.emit('close')
  }
}

function encode (data: any, encoding?: string) {
  if (!encoding) return data
  switch (encoding) {
    case 'JSON': return JSON.stringify(data)
    default: throw new Error('Unsupported channel encoding: ' + encoding)
  }
}

function decode (data: string, encoding?: string) {
  if (!encoding) return data
  switch (encoding) {
    case 'JSON': return JSON.parse(data)
    default: throw new Error('Unsupported channel encoding: ' + encoding)
  }
}
