import { JsonController } from './json.ts'

import type { Sender } from '../senders/sender'

export class ConnectionController extends JsonController {
  constructor (sender: Sender) {
    super(sender, 'urn:x-cast:com.google.cast.tp.connection')
    this.channel.addListener('message', ({ type }) => {
      try {
        if (type === 'CLOSE') sender.client.close()
      } catch (error) {}
    })
  }

  connect () {
    this.channel.send({ type: 'CONNECT' })
  }

  close () {
    this.channel.send({ type: 'CLOSE' })
  }
}
