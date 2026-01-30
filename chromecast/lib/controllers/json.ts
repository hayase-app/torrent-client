import type Channel from '../castproto/channel.ts'
import type { Sender } from '../senders/sender.ts'

export class JsonController {
  channel: Channel
  constructor (sender: Sender, namespace: string) {
    sender.client.once('close', () => {
      try {
        this.channel.close()
      } catch (error) {}
    })
    this.channel = sender.client.createChannel(sender.senderId, sender.receiverId, namespace, 'JSON')
  }
}
