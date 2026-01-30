import { once } from 'node:events'

import type { Client } from '../castproto/client.ts'

export class Sender {
  client
  senderId
  receiverId
  constructor (client: Client, senderId: string, receiverId: string) {
    this.client = client
    this.senderId = senderId
    this.receiverId = receiverId
  }

  async close () {
    this.senderId = null!
    this.receiverId = null!
    this.client = null!
    try {
      this.client.close()
      await once(this.client, 'close')
    } catch (e) {}
  }
}
