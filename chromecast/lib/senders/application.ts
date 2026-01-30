import { ConnectionController } from '../controllers/connection.ts'

import { Sender } from './sender.ts'

import type { ApplicationInfo, Client } from '../castproto/client.ts'

export class Application extends Sender {
  session
  connection
  constructor (client: Client, session: ApplicationInfo) {
    super(client, 'client-' + Math.floor(Math.random() * 10e5), session.transportId)

    this.session = session

    this.connection = new ConnectionController(this)
    this.connection.connect()
  }

  static APP_ID = ''
}
