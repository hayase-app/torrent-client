import { RequestResponseController, type AnyRequestMessage, type AnyResponseMessage } from './request-response.ts'

import type { Sender } from '../senders/sender'
import type { MediaStatusMessage } from 'castv2'
import type { LoadRequestData } from 'chromecast-caf-receiver/cast.framework.messages'

export class MediaController extends RequestResponseController {
  currentSession?: MediaStatusMessage['status'][0]
  constructor (sender: Sender) {
    super(sender, 'urn:x-cast:com.google.cast.media')

    const onmessage = (data: AnyResponseMessage, broadcast: boolean) => {
      if (data.type === 'MEDIA_STATUS' && broadcast) {
        const status = data.status[0]
        // Sometimes an empty status array can come through; if so don't emit it
        if (!status) return
        this.currentSession = status
      }
    }

    const onclose = () => {
      this.channel.removeListener('message', onmessage)
    }

    this.channel.on('message', onmessage)
    this.channel.once('close', onclose)
  }

  async getStatus () {
    const response = await this.request({ type: 'GET_STATUS' })
    const status = response.status[0]
    this.currentSession = status
    return status
  }

  async load (media: LoadRequestData['media']) {
    const data: AnyRequestMessage = { type: 'LOAD' }

    data.autoplay ??= true
    data.currentTime ??= 0
    data.activeTrackIds ??= []
    data.repeatMode ??= 'REPEAT_OFF'

    data.media = media

    const response = await this.request(data)
    if (response.type === 'LOAD_FAILED') throw new Error('Load failed')
    if (response.type === 'LOAD_CANCELLED') throw new Error('Load cancelled')
    const status = response.status[0]
    return status
  }

  async sessionRequest (data: AnyRequestMessage) {
    data.mediaSessionId = this.currentSession?.mediaSessionId
    const response = await this.request(data)
    const status = response.status[0]
    return status
  }

  play () { return this.sessionRequest({ type: 'PLAY' }) }
  pause () { return this.sessionRequest({ type: 'PAUSE' }) }
  stop () { return this.sessionRequest({ type: 'STOP' }) }
  seek (currentTime: number) { return this.sessionRequest({ type: 'SEEK', currentTime }) }

  // Load a queue of items to play (playlist)
  // See https://developers.google.com/cast/docs/reference/chrome/chrome.cast.media.QueueLoadRequest
  // async queueLoad (items, options: any = {}) {
  //   const data: any = { type: 'QUEUE_LOAD' }

  //   data.repeatMode = (typeof options.repeatMode === 'string' &&
  //     typeof options.repeatMode !== 'undefined')
  //     ? options.repeatMode
  //     : 'REPEAT_OFF'

  //   data.currentTime = (typeof options.currentTime !== 'undefined')
  //     ? options.currentTime
  //     : 0

  //   data.startIndex = (typeof options.startIndex !== 'undefined')
  //     ? options.startIndex
  //     : 0

  //   data.items = items

  //   const response = await this.request(data)
  //   if (response.type === 'LOAD_FAILED') throw new Error('queueLoad failed')
  //   if (response.type === 'LOAD_CANCELLED') throw new Error('queueLoad cancelled')
  //   const status = response.status[0]
  //   return status
  // }

  // async queueInsert (items, options: any = {}) {
  //   const data = {
  //     type: 'QUEUE_INSERT',
  //     currentItemId: options.currentItemId,
  //     currentItemIndex: options.currentItemIndex,
  //     currentTime: options.currentTime,
  //     insertBefore: options.insertBefore,
  //     items
  //   }

  //   return await this.sessionRequest(data)
  // }

  // async queueRemove (itemIds, options: any = {}) {
  //   const data = {
  //     type: 'QUEUE_REMOVE',
  //     currentItemId: options.currentItemId,
  //     currentTime: options.currentTime,
  //     itemIds
  //   }

  //   return await this.sessionRequest(data)
  // }

  // async queueReorder (itemIds, options: any = {}) {
  //   const data = {
  //     type: 'QUEUE_REORDER',
  //     currentItemId: options.currentItemId,
  //     currentTime: options.currentTime,
  //     insertBefore: options.insertBefore,
  //     itemIds
  //   }

  //   return await this.sessionRequest(data)
  // }

  // async queueUpdate (items, options: any = {}) {
  //   const data = {
  //     type: 'QUEUE_UPDATE',
  //     currentItemId: options.currentItemId,
  //     currentTime: options.currentTime,
  //     jump: options.jump,
  //     repeatMode: options.repeatMode,
  //     items
  //   }

  //   return await this.sessionRequest(data)
  // }
}
