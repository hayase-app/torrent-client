import { MediaController } from '../controllers/media.ts'

import { Application } from './application.ts'

import type { ApplicationInfo, Client } from '../castproto/client.ts'

export class DefaultMediaReceiver extends Application {
  media
  constructor (client: Client, session: ApplicationInfo) {
    super(client, session)

    this.media = new MediaController(this)
  }

  static APP_ID = 'CC1AD845'
}
