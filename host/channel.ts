import EventEmitter from 'node:events'

import { arr2base } from 'uint8-util'

import { channelKey, encrypt } from './util.ts'

import type { Http2ServerResponse } from 'node:http2'

export class Channel extends EventEmitter<{ message: [data: unknown] }> {
  id
  _key: Promise<CryptoKey>
  _clients = new Set<Http2ServerResponse>()

  constructor (id: string) {
    super()
    this.id = id
    this._key = channelKey(id)
  }

  async postMessage (message: unknown) {
    const event = `data: ${arr2base(await encrypt(await this._key, message))}\n\n`
    for (const client of this._clients) client.write(event)
  }

  _attach (response: Http2ServerResponse) {
    this._clients.add(response)
  }

  _detach (response: Http2ServerResponse) {
    this._clients.delete(response)
    return this._clients.size === 0
  }
}
