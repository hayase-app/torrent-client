import { JsonController } from './json.ts'

import type { AnyRequestMessage } from './request-response.ts'
import type { Sender } from '../senders/sender'

const DEFAULT_INTERVAL = 5 // seconds
const TIMEOUT_FACTOR = 3 // timeouts after 3 intervals

export class HeartbeatController extends JsonController {
  pingTimer?: ReturnType<typeof setTimeout>
  timeout?: ReturnType<typeof setTimeout>
  client
  constructor (sender: Sender) {
    super(sender, 'urn:x-cast:com.google.cast.tp.heartbeat')

    this.client = sender.client
    this.channel.once('close', () => this.stop())
  }

  ping () {
    if (this.timeout) {
      // We already have a ping in progress.
      return
    }

    this.timeout = setTimeout(() => {
      try {
        this.client.close()
      } catch (error) {}
      this.stop()
    }, DEFAULT_INTERVAL * 1000 * TIMEOUT_FACTOR).unref()

    const onmessage = (data: AnyRequestMessage, broadcast: boolean) => {
      if (data.type !== 'PONG') return
      clearTimeout(this.timeout)
      this.timeout = null!

      this.channel.removeListener('message', onmessage)

      this.pingTimer = setTimeout(() => {
        this.pingTimer = null!
        this.ping()
      }, DEFAULT_INTERVAL * 1000)
    }

    this.channel.on('message', onmessage)
    this.channel.send({ type: 'PING' })
  }

  stop () {
    if (this.pingTimer) {
      clearTimeout(this.pingTimer)
    }
    if (this.timeout) {
      clearTimeout(this.timeout)
    }
    this.channel.removeAllListeners('message')
  }
}
