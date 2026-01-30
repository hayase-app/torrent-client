import { RequestResponseController, type AnyResponseMessage } from './request-response.ts'

import type { Sender } from '../senders/sender'

export class ReceiverController extends RequestResponseController {
  constructor (sender: Sender) {
    super(sender, 'urn:x-cast:com.google.cast.receiver')

    const onmessage = (data: AnyResponseMessage, broadcast: boolean) => {
      if (!broadcast) return
      if (data.type === 'RECEIVER_STATUS') {
        // this.emit('status', data.status)
      }
    }

    const onclose = () => {
      this.channel.removeListener('message', onmessage)
    }

    this.channel.on('message', onmessage)
    this.channel.once('close', onclose)
  }

  async getStatus () {
    return await this.request({ type: 'GET_STATUS' })
  }

  async getAppAvailability (appId: string | string[]) {
    const data = {
      type: 'GET_APP_AVAILABILITY',
      appId: Array.isArray(appId) ? appId : [appId]
    } as const

    const response = await this.request(data)
    return response.availability
  }

  async launch (appId: string) {
    const response = await this.request({ type: 'LAUNCH', appId })
    if (response.type === 'LAUNCH_ERROR') throw new Error('Launch failed. Reason: ' + response.reason)
    return response.status.applications ?? []
  }

  async stop (sessionId: string) {
    const response = await this.request({ type: 'STOP', sessionId })
    return response.status.applications ?? []
  }

  async setVolume (options: { level: number, muted: boolean }) {
    const data = {
      type: 'SET_VOLUME',
      volume: options
    } as const

    const response = await this.request(data)
    return response.status.volume
  }

  async getVolume () {
    const status = await this.getStatus()
    return status.volume
  }

  async getSessions () {
    const status = await this.getStatus()
    return status.applications ?? []
  }
}
