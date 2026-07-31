import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { readFile, writeFile, statfs, unlink, mkdir, readdir, access, constants } from 'node:fs/promises'
import { join } from 'node:path'
import { exit } from 'node:process'
import querystring from 'querystring'

import NatAPI from '@silentbot1/nat-api'
import bencode from 'bencode'
import BitField from 'bitfield'
import DHT from 'bittorrent-dht'
import peerid from 'bittorrent-peerid'
import debug from 'debug'
// @ts-expect-error no export
import HTTPTracker from 'http-tracker'
import networkAddress from 'network-address'
import parseTorrent from 'parse-torrent'
import { hex2bin, arr2hex, text2arr, concat } from 'uint8-util'
import WebTorrent from 'webtorrent'

// import DoHResolver from './doh'
import { ChromeCasts } from './chromecast/index.ts'
import { DLNAs } from './dlna/index.ts'
import DoHResolver from './doh'
import attachments from './ebml/attachments.ts'
import { HTTPManager } from './http.ts'
import { NZBManager } from './nzb.ts'

import type { PROVIDERS } from './doh'
import type { MediaInformation } from 'chromecast-caf-receiver/cast.framework.messages'
import type { LibraryEntry, PeerInfo, TorrentFile, TorrentInfo, ClientSettings } from 'native'
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import type Torrent from 'webtorrent/lib/torrent.js'

interface ScrapeResponse { hash: string, complete: string, downloaded: string, incomplete: string }

const sleep = (t: number) => new Promise(resolve => setTimeout(resolve, t).unref())

const querystringStringify = (obj: Record<string, string>) => {
  let ret = querystring.stringify(obj, undefined, undefined, { encodeURIComponent: escape })
  ret = ret.replace(/[@*/+]/g, char => // `escape` doesn't encode the characters @*/+ so we do it manually
  `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
  return ret
}

const DHT_BOOTSTRAP = [
  { host: 'dht.libtorrent.org', port: 25401 },
  { host: 'dht.transmissionbt.com', port: 6881 },
  { host: 'router.bittorrent.com', port: 6881 }
]

const DHT_TEST_INFOHASH = Buffer.from('dd8255ecd7ca55fb0bbf81323d87062db1f6d1c', 'hex')

interface TorrentMetadata {
  info: unknown
  announce?: string[]
  urlList?: string[]
  private?: boolean
  bitfield?: Uint8Array
  date: number
  mediaID: number
  episode: number
  background?: boolean
}

interface TorrentData {
  info: unknown
  'announce-list'?: Uint8Array[][]
  'url-list'?: string[]
  private?: number
  _bitfield?: Uint8Array
  announce?: string
  date: number
  mediaID: number
  episode: number
  background?: number
}

function structTorrent ({ info, urlList, bitfield, announce, private: priv, mediaID, episode, date, background }: TorrentMetadata) {
  const torrent: TorrentData = {
    info,
    'url-list': urlList ?? [],
    _bitfield: bitfield,
    'announce-list': (announce ?? []).map(url => [text2arr(url)]),
    date,
    mediaID,
    episode
  }
  torrent.announce ??= announce?.[0]
  if (priv !== undefined) torrent.private = Number(priv)
  if (background !== undefined) torrent.background = Number(background)

  return torrent
}

const ANNOUNCE = [
  // WSS trackers, for now WebRTC is disabled
  // atob('d3NzOi8vdHJhY2tlci5vcGVud2VidG9ycmVudC5jb20='),
  // atob('d3NzOi8vdHJhY2tlci53ZWJ0b3JyZW50LmRldg=='),
  // atob('d3NzOi8vdHJhY2tlci5maWxlcy5mbTo3MDczL2Fubm91bmNl'),
  // atob('d3NzOi8vdHJhY2tlci5idG9ycmVudC54eXov'),
  atob('dWRwOi8vb3Blbi5zdGVhbHRoLnNpOjgwL2Fubm91bmNl'),
  atob('aHR0cDovL255YWEudHJhY2tlci53Zjo3Nzc3L2Fubm91bmNl'),
  atob('dWRwOi8vdHJhY2tlci5vcGVudHJhY2tyLm9yZzoxMzM3L2Fubm91bmNl'),
  atob('dWRwOi8vZXhvZHVzLmRlc3luYy5jb206Njk2OS9hbm5vdW5jZQ=='),
  atob('dWRwOi8vdHJhY2tlci5jb3BwZXJzdXJmZXIudGs6Njk2OS9hbm5vdW5jZQ=='),
  atob('dWRwOi8vOS5yYXJiZy50bzoyNzEwL2Fubm91bmNl'),
  atob('dWRwOi8vdHJhY2tlci50b3JyZW50LmV1Lm9yZzo0NTEvYW5ub3VuY2U='),
  atob('aHR0cDovL29wZW4uYWNnbnh0cmFja2VyLmNvbTo4MC9hbm5vdW5jZQ=='),
  atob('aHR0cDovL2FuaWRleC5tb2U6Njk2OS9hbm5vdW5jZQ=='),
  atob('aHR0cDovL3RyYWNrZXIuYW5pcmVuYS5jb206ODAvYW5ub3VuY2U='),
  atob('aHR0cHM6Ly90cmFja2VyLm5la29idC50by9hcGkvdHJhY2tlci9wdWJsaWMvYW5ub3VuY2U=')
]

const client = Symbol('client')
const server = Symbol('server')
const store = Symbol('store')
const path = Symbol('path')
const opts = Symbol('opts')
const tmp = Symbol('tmp')
const doh = Symbol('doh')
const nzb = Symbol('nzb')
const http = Symbol('http')
const tracker = new HTTPTracker({}, atob('aHR0cDovL255YWEudHJhY2tlci53Zjo3Nzc3L2Fubm91bmNl'))

class Store {
  cacheFolder
  constructor (path: string) {
    const targetPath = join(path, 'hayase-cache')
    this.cacheFolder = mkdir(targetPath, { recursive: true }).then(() => targetPath)
  }

  async get (key?: string) {
    if (!key) return null
    try {
      const data = await readFile(join(await this.cacheFolder, key))
      if (!data.length) return
      // this double decoded bencoded data, unfortunate, but I wish to preserve my sanity
      // @ts-expect-error bad typedefs
      const bencoded = bencode.decode(data) as TorrentData
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/await-thenable
      const torrent: any = await parseTorrent(data)

      return { bencoded, torrent }
    } catch (error) {
      // means it doesnt exist
    }
  }

  async set (key: string, value: TorrentData) {
    try {
      // @ts-expect-error bad typedefs
      return await writeFile(join(await this.cacheFolder, key), bencode.encode(value), { mode: 0o666 })
    } catch (e) {
      console.error(e)
    }
  }

  async delete (key: string) {
    try {
      return await unlink(join(await this.cacheFolder, key))
    } catch (err) {
      return null
    }
  }

  async * entries () {
    try {
      const files = await readdir(await this.cacheFolder, { withFileTypes: true })
      for (const file of files) {
        if (!file.isDirectory()) {
          const res = await this.get(file.name)
          if (res) yield res
        }
      }
    } catch (error) {
      console.error(error)
    }
  }

  async list () {
    try {
      return (await readdir(await this.cacheFolder, { withFileTypes: true }))
        .filter(item => !item.isDirectory())
        .map(({ name }) => name)
    } catch (err) {
      return []
    }
  }
}

const megaBitsToBytes = 1024 * 1024 / 8

process.on('uncaughtException', err => console.error(err))
process.on('unhandledRejection', err => console.error(err))

// this could... be a bad idea and needs to be verified
const peerId = concat([[45, 113, 66, 53, 48, 51, 48, 45], randomBytes(12)])

// this is what we in the industry call shitcode
// if you want to improve it, don't. re-write it from scratch
export default class TorrentClient {
  [client]: WebTorrent
  [server]: Server
  [store]: Store
  [path]: string
  [opts]: Record<string, unknown>
  [tmp]: string
  [doh]?: DoHResolver
  [nzb]?: NZBManager
  [http] = new HTTPManager()
  sessions = new Map<string, string>()
  torrentState = new Map<string, {
    background: boolean
    mediaID: number
    episode: number
    torrent: Torrent
  }>()

  attachments = attachments

  chromecasts = new ChromeCasts(attachments)
  dlnas = new DLNAs()

  streamed = false
  persist = false

  constructor (settings: ClientSettings & {path: string }, temp: string) {
    this[opts] = {
      dht: !settings.torrentDHT && { bootstrap: DHT_BOOTSTRAP },
      utPex: !settings.torrentPeX,
      downloadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes),
      uploadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes * 1.2),
      natUpnp: 'permanent',
      userAgent: 'curl/7.81.0',
      torrentPort: settings.torrentPort,
      dhtPort: settings.dhtPort,
      maxConns: settings.maxConns,
      peerId,
      secure: 1
    }
    this[client] = new WebTorrent(this[opts])
    if (settings.nzbDomain && settings.nzbPort && settings.nzbLogin && settings.nzbPassword && settings.nzbPoolSize) {
      this[nzb] = new NZBManager(settings.nzbDomain, settings.nzbPort, settings.nzbLogin, settings.nzbPassword, settings.nzbPoolSize)
    }
    this[client].on('error', console.error)
    // @ts-expect-error bad types
    this[server] = this[client].createServer({}, 'node').listen(0)
    this[tmp] = temp
    this[path] = settings.path || temp
    this[store] = new Store(this[path])
    // try {
    //   if (settings.doh) this[doh] = new DoHResolver(settings.doh)
    // } catch (error) {
    //   console.error(error)
    // }
    this.streamed = settings.torrentStreamedDownload
    this.persist = settings.torrentPersist
    this.loadBackgroundDownloads()
  }

  updateSettings (settings: ClientSettings & { path: string }) {
    this[client].throttleDownload(Math.round(settings.torrentSpeed * megaBitsToBytes))
    this[client].throttleUpload(Math.round(settings.torrentSpeed * megaBitsToBytes * 1.2))
    this[opts] = {
      dht: !settings.torrentDHT && { bootstrap: DHT_BOOTSTRAP },
      utPex: !settings.torrentPeX,
      downloadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes),
      uploadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes * 1.2),
      natUpnp: 'permanent',
      torrentPort: settings.torrentPort,
      dhtPort: settings.dhtPort,
      maxConns: settings.maxConns,
      peerId,
      secure: 1
    }
    this[path] = settings.path || this[tmp]
    this[nzb]?.destroy()
    if (settings.nzbDomain && settings.nzbPort && settings.nzbLogin && settings.nzbPassword && settings.nzbPoolSize) {
      this[nzb] = new NZBManager(settings.nzbDomain, settings.nzbPort, settings.nzbLogin, settings.nzbPassword, settings.nzbPoolSize)
    }
    this[store] = new Store(this[path])
    this.streamed = settings.torrentStreamedDownload
    this.persist = settings.torrentPersist
  }

  async setDOH (dohServer: `https://${keyof typeof PROVIDERS}`) {
    await this[doh]?.destroy()
    try {
      this[doh] = new DoHResolver(dohServer)
    } catch (error) {
      console.error(error)
    }
  }

  // WARN: ONLY CALL THIS DURING SETUP!!!
  async checkIncomingConnections (testPort: number): Promise<boolean> {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 30_000).unref()
    const dht = new DHT({ bootstrap: DHT_BOOTSTRAP })
    dht.on('error', () => {})
    dht.listen(testPort)
    await once(dht, 'listening')
    await once(dht, 'ready')

    const actualPort = dht.address().port
    const nat = new NatAPI({ enableUPNP: true, enablePMP: true, upnpPermanentFallback: true })
    try {
      if (!await nat.map({ publicPort: actualPort, privatePort: actualPort, protocol: null })) return false
    } catch {
      return false
    } finally {
      await nat.destroy()
    }

    dht.announce(DHT_TEST_INFOHASH, actualPort)

    try {
      await Promise.race([
        once(dht, 'announce_peer', ctrl),
        once(dht, 'get_peers', ctrl)
      ])
      return true
    } catch {
      return false
    } finally {
      clearTimeout(timer)
      await new Promise<void>(resolve => dht.destroy(resolve))
    }
  }

  async checkAvailableSpace () {
    const { bsize, bavail } = await statfs(this[path])
    return bsize * bavail
  }

  async scrape (infoHashes: string[]): Promise<ScrapeResponse[]> {
    // this seems to give the best speed, and lowest failure rate
    const MAX_ANNOUNCE_LENGTH = 1300 // it's likely 2048, but lets undercut it
    const RATE_LIMIT = 200 // ms

    const ANNOUNCE_LENGTH = tracker.scrapeUrl.length

    let batch: string[] = []
    let currentLength = ANNOUNCE_LENGTH // fuzz the size a little so we don't always request the same amt of hashes
    const results: ScrapeResponse[] = []

    const scrape = async () => {
      if (results.length) await sleep(RATE_LIMIT)
      const data = await new Promise((resolve, reject) => {
        tracker._request(tracker.scrapeUrl, { info_hash: batch }, (err: Error | null, data: unknown) => {
          if (err) return reject(err)
          resolve(data)
        })
      })

      const { files } = data as { files: Array<Pick<ScrapeResponse, 'complete' | 'downloaded' | 'incomplete'>> }
      const result = []
      for (const [key, data] of Object.entries(files)) {
        result.push({ hash: key.length !== 40 ? arr2hex(text2arr(key)) : key, ...data })
      }

      results.push(...result)
      batch = []
      currentLength = ANNOUNCE_LENGTH
    }

    for (const infoHash of infoHashes.sort(() => 0.5 - Math.random()).map(infoHash => hex2bin(infoHash))) {
      const qsLength = querystringStringify({ info_hash: infoHash }).length + 1 // qs length + 1 for the & or ? separator
      if (currentLength + qsLength > MAX_ANNOUNCE_LENGTH) {
        await scrape()
      }

      batch.push(infoHash)
      currentLength += qsLength
    }
    if (batch.length) await scrape()

    return results
  }

  async toInfoHash (torrentId: string | ArrayBufferView) {
    let parsed: { infoHash: string } | undefined

    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/await-thenable
    try { parsed = await parseTorrent(torrentId) as any } catch (err) {}
    return parsed?.infoHash
  }

  async playTorrent (
    id: string | ArrayBufferView,
    mediaID: number,
    episode: number,
    sessionID: string,
    background?: boolean
  ): Promise<TorrentFile[]> {
    const infoHash = await this.toInfoHash(id)
    if (!infoHash) throw new Error('Invalid torrent identifier')
    background = !!background

    const oldHash = !background ? this.sessions.get(sessionID) : undefined
    if (!background) this.sessions.set(sessionID, infoHash)

    const torrent = await this.initTorrent(infoHash, id, !background && this.streamed, background, mediaID, episode)

    if (oldHash && oldHash !== infoHash) await this.evictOrphan(oldHash)

    this.updateTorrentPriority(infoHash)
    this.updateTorrentPriority(oldHash)

    const lan = networkAddress()
    return torrent.files.map(({ name, type, size, path, streamURL }, id) => {
      const suffix = ':' + (this[server].address() as AddressInfo).port + streamURL
      return {
        hash: torrent.infoHash, name, type, size, path, id, url: 'http://localhost' + suffix, lan: 'http://' + lan + suffix
      }
    })
  }

  async rescanTorrents (hashes: string[]) {
    const tmpclient = new WebTorrent({
      dht: false,
      utPex: false,
      downloadLimit: 0,
      maxConns: 0,
      peerId,
      secure: 1,
      tracker: {},
      natUpnp: false,
      natPmp: false,
      userAgent: 'curl/7.81.0',
      utp: false
    })

    const promises: Array<Promise<void>> = []

    const cachedStore = this[store]

    const activeHashes = new Set(this[client].torrents.map(t => t.infoHash))

    for (const hash of hashes) {
      if (activeHashes.has(hash)) continue
      promises.push(
        (async () => {
          const storeData = await cachedStore.get(hash)
          if (!storeData) return
          const torrent = tmpclient.add(storeData.torrent, { path: this[path], announce: [], deselect: true, paused: true })

          await new Promise(resolve => torrent.once('ready', resolve))

          cachedStore.set(torrent.infoHash, structTorrent({
            // @ts-expect-error bad typedefs
            info: torrent.info,
            announce: torrent.announce,
            private: torrent.private,
            urlList: torrent.urlList,
            bitfield: torrent.bitfield!.buffer,
            date: Date.now(),
            mediaID: storeData.bencoded.mediaID,
            episode: storeData.bencoded.episode
          }))

          await new Promise(resolve => tmpclient.remove(torrent, { destroyStore: false }, resolve))
        })()
      )
    }

    await Promise.allSettled(promises)

    await new Promise(resolve => tmpclient.destroy(resolve))
  }

  async deleteTorrents (hashes: string[]) {
    const tmpclient = new WebTorrent({
      dht: false,
      utPex: false,
      downloadLimit: 0,
      maxConns: 0,
      peerId,
      secure: 1,
      tracker: {},
      natUpnp: false,
      natPmp: false,
      userAgent: 'curl/7.81.0',
      utp: false
    })

    const cachedStore = this[store]

    const promises: Array<Promise<void>> = []

    const activeHashes = new Set(this[client].torrents.map(t => t.infoHash))

    for (const hash of hashes) {
      if (activeHashes.has(hash)) continue
      promises.push(
        (async () => {
          const storeData = await cachedStore.get(hash)
          if (!storeData) return

          const torrent = tmpclient.add(storeData.torrent, { path: this[path], announce: [], deselect: true, paused: true, skipVerify: true })

          if (!torrent.ready) await new Promise(resolve => torrent.once('ready', resolve))

          await new Promise(resolve => tmpclient.remove(torrent, { destroyStore: true }, resolve))

          await cachedStore.delete(hash)
        })()
      )
    }

    await Promise.allSettled(promises)

    await new Promise(resolve => tmpclient.destroy(resolve))
  }

  async cached () {
    return await this[store].list()
  }

  // TODO: use https://www.npmjs.com/package/comlink-async-generator?activeTab=code
  async library () {
    const torrents: LibraryEntry[] = []
    for await (const { torrent, bencoded } of this[store].entries()) {
      const bitfield = new BitField(bencoded._bitfield ?? new Uint8Array(0))

      let downloaded = 0
      for (let index = 0, len = torrent.pieces.length; index < len; ++index) {
        if (bitfield.get(index)) { // verified data
          downloaded += (index === len - 1) ? torrent.lastPieceLength : torrent.pieceLength
        }
      }
      const progress = torrent.length ? downloaded / torrent.length : 0

      torrents.push({
        mediaID: bencoded.mediaID,
        episode: bencoded.episode,
        files: torrent.files.length,
        hash: torrent.infoHash,
        progress,
        date: bencoded.date,
        size: torrent.length,
        name: torrent.name
      })
    }
    return torrents
  }

  async trackers (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')

    torrent.discovery?.tracker.scrape({
      infoHash: torrent.infoHash,
      announce: torrent.announce,
      peerId: torrent.client.peerId,
      port: torrent.client.torrentPort
    })

    const responses: Array<{ complete: number, downloaded: number, incomplete: number, announce: string, failed?: boolean }> = []
    torrent.discovery?.tracker.on('scrape', (res: { complete: number, downloaded: number, incomplete: number, announce: string }) => {
      responses.push(res)
    })

    await sleep(5_000)

    torrent.discovery?.tracker.removeAllListeners('scrape')

    const mappedResponses = Object.fromEntries(responses.map(({ complete, downloaded, incomplete, announce }) => [announce, { complete, downloaded, incomplete, failed: false }]))

    for (const { announceUrl } of torrent.discovery?.tracker._trackers) {
      mappedResponses[announceUrl] ??= { complete: 0, downloaded: 0, incomplete: 0, failed: true }
    }

    return mappedResponses
  }

  errors (cb: (errors: Error) => void) {
    this[client].on('error', err => cb(err))
    process.on('uncaughtException', err => cb(err))
  }

  debug (levels: string) {
    debug.disable()
    if (levels) debug.enable(levels)
  }

  torrents () {
    return this[client].torrents.map(t => this.makeStats(t))
  }

  async createNZBWebSeed (id: string, url: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')

    await this[nzb]?.addNZBPeers(torrent, url)
  }

  async createHTTPWebSeed (id: string, url: string, authorization?: string, fileIndex?: number, rateLimit?: number) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')

    await this[http].addHTTPPeers(torrent, url, authorization, fileIndex, rateLimit)
  }

  async torrentInfo (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')
    return this.makeStats(torrent)
  }

  async peerInfo (id: string) {
    const torrent = await this[client].get(id)

    if (!torrent) throw new Error('Torrent not found')
    const peers: PeerInfo[] = torrent.wires.map(wire => {
      const flags: Array<'incoming' | 'outgoing' | 'utp' | 'encrypted'> = []

      const type = wire.type
      if (type.startsWith('utp')) flags.push('utp')
      flags.push(type.endsWith('Incoming') ? 'incoming' : 'outgoing')
      if (wire._cryptoHandshakeDone) flags.push('encrypted')

      const parsed = peerid(wire.peerId!)

      const progress = this._wireProgress(wire, torrent)

      const isWebSeed = wire.type === 'webSeed'
      // @ts-expect-error bad typedefs
      const ip = isWebSeed ? (wire.domain ?? wire.remoteAddress) : wire.remoteAddress.replace(/^::ffff:/, '') + ':' + wire.remotePort
      // @ts-expect-error bad typedefs
      const client = isWebSeed ? (wire.webSeedType ?? 'http') : `${parsed.client} ${parsed.version ?? ''}`

      return {
        ip,
        // @ts-expect-error bad typedefs
        seeder: wire.isSeeder,
        client,
        progress,
        size: {
          downloaded: wire.downloaded,
          uploaded: wire.uploaded
        },
        speed: {
          down: wire.downloadSpeed(),
          up: wire.uploadSpeed()
        },
        time: 0,
        flags
      }
    })

    return peers
  }

  async verifyDirectoryPermissions (path: string) {
    try {
      await access(path || this[tmp], constants.R_OK | constants.W_OK)
    } catch {
      throw new Error(`Insufficient permissions to access directory: ${path}`)
    }
  }

  _wireProgress (wire: Torrent['wires'][number], torrent: Torrent): number {
    if (!wire.peerPieces) return 0
    let downloaded = 0
    for (let index = 0, len = torrent.pieces.length; index < len; ++index) {
      if (wire.peerPieces.get(index)) { // verified data
        // @ts-expect-error bad typedefs
        downloaded += (index === len - 1) ? torrent.lastPieceLength : torrent.pieceLength
      }
    }
    // @ts-expect-error bad typedefs
    return torrent.length ? downloaded / torrent.length : 0
  }

  async evictOrphan (infoHash: string) {
    const entry = this.torrentState.get(infoHash)
    if (!entry || entry.background) return

    if (this.sessions.values().some(h => h === infoHash)) return

    if (entry.torrent.destroyed) {
      this.torrentState.delete(infoHash)
      return
    }

    await new Promise(resolve => this[client].remove(entry.torrent, { destroyStore: !this.persist }, resolve))
    if (!this.persist) await this[store].delete(infoHash)
  }

  setupBitfieldSave (torrent: Torrent, mediaID: number, episode: number, background = false) {
    if (torrent.done) return

    const cachedStore = this[store]
    const savebitfield = () => cachedStore.set(torrent.infoHash, structTorrent({
      // @ts-expect-error bad typedefs
      info: torrent.info,
      announce: torrent.announce,
      private: torrent.private,
      urlList: torrent.urlList,
      bitfield: torrent.bitfield!.buffer,
      date: Date.now(),
      mediaID,
      episode,
      background
    }))

    const interval = setInterval(savebitfield, 1000 * 20).unref()
    savebitfield()

    torrent.on('done', () => {
      savebitfield()
      clearInterval(interval)
    })
    torrent.once('close', () => clearInterval(interval))
  }

  updateTorrentPriority (infoHash?: string) {
    if (!infoHash) return
    const entry = this.torrentState.get(infoHash)
    if (!entry) return

    const { torrent, background } = entry
    if (torrent.destroyed) return

    const sessionCount = [...this.sessions.values()].filter(h => h === infoHash).length
    const downloadLimit = this[opts].downloadLimit as number

    if (background) {
      torrent.select()
    } else if (this.streamed) {
      torrent.deselect()
    }

    if (sessionCount === 0) {
      if (background) {
        torrent.setPriority(1)
        torrent.throttleDownloadSpeed(downloadLimit === -1 ? -1 : Math.round(downloadLimit * 0.3))
      }
      return
    }

    // if (background) {
    //   // background download with active sessions
    //   torrent.setPriority(7)
    //   torrent.throttleDownloadSpeed(-1)
    //   torrent.throttleUploadSpeed(-1)
    //   return
    // }
    torrent.setPriority(sessionCount > 1 ? 10 : 5)
    torrent.throttleDownloadSpeed(-1)
  }

  async initTorrent (infoHash: string, source: string | ArrayBufferView | object, deselect: boolean, background: boolean, mediaID: number, episode: number): Promise<Torrent> {
    const existing = await this[client].get(infoHash)
    const storeData = !existing ? await this[store].get(infoHash) : undefined

    const torrent = existing ?? this[client].add(storeData?.torrent ?? source, {
      path: this[path],
      announce: ANNOUNCE,
      bitfield: storeData?.bencoded._bitfield,
      deselect
    })

    if (!torrent.ready) await once(torrent, 'ready')

    if (this.torrentState.has(infoHash)) {
      const prev = this.torrentState.get(infoHash)!
      prev.mediaID = mediaID
      prev.episode = episode
      prev.background ||= background
    } else {
      this.torrentState.set(infoHash, { background, mediaID, episode, torrent })
      torrent.once('close', () => {
        if (this.torrentState.get(infoHash)?.torrent === torrent) {
          this.torrentState.delete(infoHash)
        }
      })
      this.setupBitfieldSave(torrent, mediaID, episode, background)
      this.attachments.register(torrent)
      await this[nzb]?.register(torrent)
    }

    return torrent
  }

  async loadBackgroundDownloads () {
    for await (const { bencoded, torrent: parsed } of this[store].entries()) {
      if (!bencoded.background) continue
      if (this.torrentState.has(parsed.infoHash)) continue

      await this.initTorrent(parsed.infoHash, parsed, false, true, bencoded.mediaID, bencoded.episode)
    }
  }

  async stopSession (sessionID: string) {
    const infoHash = this.sessions.get(sessionID)
    if (!infoHash) return
    this.sessions.delete(sessionID)
    this.updateTorrentPriority(infoHash)
    await this.evictOrphan(infoHash)
  }

  activeTorrents () {
    return this[client].torrents.map(t => this.makeStats(t))
  }

  async fileInfo (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')
    return torrent.files.map(({ name, length, progress, _iterators }) => ({
      name,
      size: length,
      progress,
      selections: _iterators.size
    }))
  }

  async protocolStatus (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')
    return {
      dht: !!this[client].dhtPort,
      lsd: !!torrent.discovery?.lsd?.server,
      pex: !torrent.private,
      nat: !!this[client].natTraversal?._pmpClient && !!this[client].natTraversal?._upnpClient, //! !await this[client].natTraversal?.externalIp(),
      forwarding: !!torrent._peers.values().find(peer => peer.type === 'utpIncoming' || peer.type === 'tcpIncoming'),
      persisting: !!this.persist,
      streaming: !!torrent._startAsDeselected
    }
  }

  makeStats (torrent: Torrent): TorrentInfo {
    // @ts-expect-error bad typedefs
    const seeders = torrent.wires.filter(wire => wire.isSeeder).length
    const leechers = torrent.wires.length - seeders
    const wires = torrent._peersLength
    // @ts-expect-error bad typedefs
    const { infoHash: hash, timeRemaining: remaining, length: total, name, progress, downloadSpeed: down, uploadSpeed: up, downloaded, uploaded, pieces, pieceLength } = torrent

    return {
      hash,
      name,
      peers: {
        seeders, leechers, wires
      },
      progress,
      speed: {
        down,
        up
      },
      size: {
        downloaded,
        uploaded,
        total
      },
      time: {
        remaining,
        elapsed: 0
      },
      pieces: {
        total: pieces.length,
        size: pieceLength
      }
    }
  }

  listenDisplay (cb: (displays: Array<{ friendlyName: string, host: string }>) => void) {
    const emit = () => cb([...Object.values(this.chromecasts.casts), ...Object.values(this.dlnas.displays)])

    this.chromecasts.listen(emit)
    this.dlnas.listen(emit)
  }

  playDisplay (host: string, hash: string, id: number, media: MediaInformation) {
    if (host.startsWith('cast://')) {
      return this.chromecasts.play(host.substring(7), hash, id, media)
    } else if (host.startsWith('dlna://')) {
      return this.dlnas.play(host.substring(7), hash, id, media)
    }
  }

  closeDisplay (host: string) {
    if (host.startsWith('cast://')) {
      return this.chromecasts.close(host.substring(7))
    } else if (host.startsWith('dlna://')) {
      return this.dlnas.close(host.substring(7))
    }
  }

  async destroy () {
    await Promise.allSettled([
      this.attachments.destroy(),
      this.chromecasts.destroy(),
      this.dlnas.destroy(),
      new Promise(resolve => this[client].destroy(resolve)),
      new Promise(resolve => tracker.destroy(resolve)),
      this[nzb]?.destroy(),
      this[http].destroy(),
      this[doh]?.destroy()
    ])
    exit()
  }
}
