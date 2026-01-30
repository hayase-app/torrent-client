import { JsonController } from '../controllers/json.ts'
import { MediaController } from '../controllers/media.ts'

import { Application } from './application.ts'

import type { ApplicationInfo, Client } from '../castproto/client.ts'

export class UrlCast extends Application {
  url
  media
  constructor (client: Client, session: ApplicationInfo) {
    super(client, session)

    this.url = new JsonController(this, 'urn:x-cast:com.url.cast')
    this.media = new MediaController(this)
  }

  static APP_ID = 'F433D22E'
}
