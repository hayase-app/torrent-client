import EventEmitter from 'node:events'

import type { ServerResponse } from 'node:http'

export class Channel extends EventEmitter<{ message: [data: unknown] }> {
  id
  _clients = new Set<ServerResponse>()

  constructor (id: string) {
    super()
    this.id = id
  }

  postMessage (message: unknown) {
    const event = `data: ${JSON.stringify(message)}\n\n`
    for (const client of this._clients) client.write(event)
  }

  _attach (response: ServerResponse) {
    this._clients.add(response)
  }

  _detach (response: ServerResponse) {
    this._clients.delete(response)
    return this._clients.size === 0
  }
}
