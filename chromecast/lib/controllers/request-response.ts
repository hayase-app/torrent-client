/* eslint-disable @typescript-eslint/no-explicit-any */
import { JsonController } from './json.ts'

export type AnyResponseMessage = { requestId?: number, type: string } & Record<string, any>
export type AnyRequestMessage = { requestId?: number, type: string } & Record<string, any>

export class RequestResponseController extends JsonController {
  lastRequestId = 0

  async request (data: AnyRequestMessage) {
    const requestId = ++this.lastRequestId

    return await new Promise<AnyResponseMessage>((resolve, reject) => {
      const onmessage = (response: AnyResponseMessage, broadcast: boolean) => {
        if (response.requestId === requestId) {
          this.channel.removeListener('message', onmessage)

          if (response.type === 'INVALID_REQUEST') {
            return reject(new Error('Invalid request: ' + response.reason))
          }

          delete response.requestId
          resolve(response)
        }
      }

      this.channel.on('message', onmessage)

      data.requestId = requestId
      this.channel.send(data)
    })
  }
}
