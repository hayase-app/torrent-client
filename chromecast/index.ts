import { EventEmitter, once } from 'node:events'

import { XMLParser } from 'fast-xml-parser'
import multicastdns from 'multicast-dns'

import decode from './lib/dns-txt.ts'
import { PlatformSender } from './lib/senders/platform.ts'
import { UrlCast } from './lib/senders/url-cast.ts'
import Ssdp from './lib/ssdp.ts'

import type Attachments from '../attachments.ts'
import type { MediaInformation } from 'chromecast-caf-receiver/cast.framework.messages'

class Cast {
  platform!: PlatformSender
  host
  friendlyName
  destroyed = false
  constructor (name: string, host: string) {
    this.host = host
    this.friendlyName = name

    this.start()
  }

  start () {
    this.platform = new PlatformSender()
    this.platform.client.on('error', async (err) => {
      console.error('Chromecast client error:', err)
      this.restart()
    })

    this.platform.client.on('close', async () => {
      this.restart()
    })
  }

  async restart () {
    if (this.destroyed) return
    if (this._ready) {
      this.platform.stop(await this._ready)
    }
    await this.platform.close()
    this._ready = undefined
    this.start()
  }

  async destroy () {
    this.destroyed = true
    if (this._ready) {
      this.platform.stop(await this._ready)
    }
    await this.platform.close()
  }

  _ready?: Promise<UrlCast>

  connect (): Promise<UrlCast> {
    this._ready = this._ready ?? this._connect()
    return this._ready
  }

  async _connect () {
    if (this.destroyed) throw new Error('Device destroyed')
    await this.platform.connect({ host: this.host })

    const sess = await this.platform.receiver?.getSessions()

    const session = sess[0]
    return session?.appId === UrlCast.APP_ID ? await this.platform.join(session, UrlCast) : await this.platform.launch(UrlCast)
  }

  // async play (url: string): Promise<void> {
  //   const p = await this.connect()

  // const media = {
  //   contentId: url
  // entity: 'bbb',
  // contentType: opts.type ?? 'video/mp4',
  // streamType: opts.streamType ?? 'BUFFERED',
  // tracks: [].concat(opts.subtitles ?? []).map(toSubtitles),
  // textTrackStyle: opts.textTrackStyle,
  // metadata: opts.metadata ?? {
  //   type: 0,
  //   metadataType: 0,
  //   title: opts.title ?? '',
  //   images: []
  // }
  // }

  // let autoSubtitles = opts.autoSubtitles
  // if (autoSubtitles === false) autoSubtitles = 0
  // if (autoSubtitles === true) autoSubtitles = 1

  //   await p.media.load({ contentId: url, contentType: 'video/mp4', streamType: 'BUFFERED' as StreamType })
  //   setTimeout(async () => {
  //     const src = 'https://storage.googleapis.com/cpe-sample-media/content/big_buck_bunny/prog/big_buck_bunny_prog.mp4'
  //     const subs = await readFile('./subs.ass', 'utf-8')
  //     p.url.channel.send({ type: 'header', subtitle: subs, src })
  //     p.url.channel.send({ type: 'eval', code: 'document.querySelector(\'cast-media-player\').shadowRoot.querySelector(\'video\')', src })
  //   }, 4000)
  //   // p.load(media, playerOptions, cb)
  //   // p.sendFrame('https://jassub.pages.dev/kusriya/jassub/', console.log)
  // }
}

export class ChromeCasts extends EventEmitter<{display: [Array<{ friendlyName: string, host: string }>]}> {
  players = new Map<string, Cast>()
  mdns = multicastdns()
  casts: Record<string, { friendlyName: string, host: string }> = {}
  ssdp = new Ssdp({ permanentFallback: true })
  // every 1 minute
  interval = setInterval(() => this.update(), 1 * 60 * 1000)
  attachments

  add (cst: { friendlyName: string, host: string }) {
    const player = this.players.get(cst.host) ?? new Cast(cst.friendlyName, cst.host)

    this.players.set(cst.host, player)
    this.emit('display', Object.values(this.casts))
  }

  listen (cb: (displays: Array<{ friendlyName: string, host: string }>) => void) {
    const existing = Object.values(this.casts)
    if (existing.length > 0) cb(existing)
    this.on('display', casts => cb(casts))
  }

  async play (host: string, hash: string, id: number, media: MediaInformation) {
    const player = this.players.get(host)
    if (!player) throw new Error('No such player')
    const conn = await player.connect()
    media.customData = { hash, id }
    await conn.media.load(media)
    const tracks = await this.attachments.tracks(hash, id)
    conn.url.channel.send({ type: 'tracks', tracks })
    this.attachments.subtitle(hash, id, (subtitle, trackNumber) => {
      conn.url.channel.send({ type: 'subtitle', subtitle, trackNumber })
    })
    const attachments = await this.attachments.attachments(hash, id)
    conn.url.channel.send({ type: 'attachments', attachments })

    await once(player.platform.client, 'close')
  }

  async close (host: string) {
    const player = this.players.get(host)
    if (!player) throw new Error('No such player')
    player.restart()
  }

  constructor (attachments: typeof Attachments) {
    super()
    this.attachments = attachments
    this.mdns.on('response', (response) => {
      // id:name
      const friendlyNames: Record<string, string> = {}
      // id:domain
      const domains: Record<string, string> = {}
      // domain:ip
      const addresses: Record<string, string> = {}
      // @ts-expect-error w/e
      for (const { type, name, data } of [...response.answers, ...response.additionals]) {
        if (type === 'A' || type === 'AAAA') addresses[name] ??= data

        if (!name.endsWith('._googlecast._tcp.local')) continue
        const id = name.replace('._googlecast._tcp.local', '') || data.replace('._googlecast._tcp.local', '')

        if (type === 'PTR') {
          friendlyNames[id] ??= id
        } else if (type === 'SRV') {
          domains[id] ??= data.target
        } else if (type === 'TXT') {
          for (const item of data) {
            for (const [key, value] of Object.entries(decode(item as Buffer))) {
              if (key === 'fn' || key === 'n') { // friendly name or name
                friendlyNames[id] = value as string
              }
            }
          }
        }
      }

      for (const [id, domain] of Object.entries(domains)) {
        const host = addresses[domain] ?? domain
        const friendlyName = friendlyNames[id] ?? id

        this.casts[id] ??= { friendlyName, host }
        this.add({ friendlyName, host })
      }
    })

    this.update()
  }

  async update () {
    this.mdns.query('_googlecast._tcp.local', 'PTR')

    const { device } = await this.ssdp.search('urn:dial-multiscreen-org:device:dial:1', 5000)
    if (!device?.url) return

    const res = await fetch(device.url)

    const x = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '' })
    const service = x.parse(await res.text()).root

    const friendlyName = service.device?.friendlyName
    if (!friendlyName) return

    const id = service.device.modelName + '-' + service.device.UDN.replace('uuid:', '').replaceAll('-', '')

    const host = new URL(service.URLBase).hostname

    this.casts[id] ??= { friendlyName, host }
    this.add({ friendlyName, host })
  }

  async destroy () {
    clearInterval(this.interval)

    return await Promise.all([
      ...this.players.values().map(player => player.destroy()),
      new Promise<void>(resolve => this.mdns.destroy(resolve)),
      this.ssdp.destroy()
    ])
  }
}
