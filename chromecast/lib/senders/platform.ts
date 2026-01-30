import { Client, type ApplicationInfo } from '../castproto/client.ts'
import { ConnectionController } from '../controllers/connection.ts'
import { HeartbeatController } from '../controllers/heartbeat.ts'
import { ReceiverController } from '../controllers/receiver.ts'

import { Sender } from './sender.ts'

import type { Application } from './application'
import type { ConnectionOptions } from 'node:tls'

export class PlatformSender extends Sender {
  connection = new ConnectionController(this)
  heartbeat = new HeartbeatController(this)
  receiver = new ReceiverController(this)
  constructor () {
    super(new Client(), 'sender-0', 'receiver-0')
  }

  async connect (options: ConnectionOptions | string) {
    await new Promise<void>((resolve, reject) => {
      const onerror = (err: Error) => {
        reject(err)
      }
      this.client.on('error', onerror)
      this.client.connect(options, resolve)
    })

    this.connection.connect()
    this.heartbeat.ping()
  }

  async close () {
    try {
      this.connection.close()
    } catch (e) {}
    return await super.close()
  }

  async getAppAvailability (appId: string | string[]) {
    const availability = await this.receiver?.getAppAvailability(appId)
    for (const key in availability) {
      availability[key] = (availability[key] === 'APP_AVAILABLE')
    }
    return availability
  }

  async join <T extends typeof Application> (session: ApplicationInfo, App: T): Promise<InstanceType<T>> {
    return new App(this.client, session) as InstanceType<T>
  }

  async launch <T extends typeof Application> (App: T) {
    const sessions = await this.receiver?.launch(App.APP_ID)
    const filtered = (sessions ?? []).filter((session: ApplicationInfo) => session.appId === App.APP_ID)
    const session = filtered.shift()
    return await this.join(session, App)
  }

  async stop (application: Application) {
    const session = application.session
    await this.receiver?.stop(session.sessionId)
    application.close()
  }
}
