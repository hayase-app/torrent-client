import { randomBytes } from 'node:crypto'
import { readFile, writeFile, statfs, unlink, mkdir, readdir, access, constants } from 'node:fs/promises'
import { join } from 'node:path'
import { exit } from 'node:process'
import querystring from 'querystring'

import bencode from 'bencode'
import BitField from 'bitfield'
import peerid from 'bittorrent-peerid'
import debug from 'debug'
// @ts-expect-error no export
import HTTPTracker from 'http-tracker'
import MemoryChunkStore from 'memory-chunk-store'
import parseTorrent from 'parse-torrent'
import { hex2bin, arr2hex, text2arr, concat } from 'uint8-util'
import WebTorrent from 'webtorrent'

import attachments from './attachments'
// import DoHResolver from './doh'
import { createNZB } from './nzb'

import type { LibraryEntry, PeerInfo, TorrentFile, TorrentInfo, TorrentSettings } from 'native'
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

interface TorrentMetadata {
  info: unknown
  announce?: string[]
  urlList?: string[]
  private?: boolean
  bitfield?: Uint8Array
  date: number
  mediaID: number
  episode: number
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
}

function structTorrent ({ info, urlList, bitfield, announce, private: priv, mediaID, episode, date }: TorrentMetadata) {
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
  atob('aHR0cDovL3RyYWNrZXIuYW5pcmVuYS5jb206ODAvYW5ub3VuY2U=')
]

const client = Symbol('client')
const server = Symbol('server')
const store = Symbol('store')
const path = Symbol('path')
const opts = Symbol('opts')
const tmp = Symbol('tmp')
// const doh = Symbol('doh')
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
      const bencoded: TorrentData = bencode.decode(data)
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/await-thenable
      const torrent: any = await parseTorrent(data)

      return { bencoded, torrent }
    } catch (error) {
      // means it doesnt exist
    }
  }

  async set (key: string, value: TorrentData) {
    try {
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

// this could... be a bad idea and needs to be verified
const peerId = concat([[45, 113, 66, 53, 48, 51, 48, 45], randomBytes(12)])

export default class TorrentClient {
  [client]: WebTorrent;
  [server]: Server;
  [store]: Store;
  [path]: string;
  [opts]: Record<string, unknown>;
  [tmp]: string
  // [doh]: DoHResolver | undefined

  attachments = attachments

  streamed = false
  persist = false

  constructor (settings: TorrentSettings & {path: string }, temp: string) {
    this[opts] = {
      dht: !settings.torrentDHT,
      utPex: !settings.torrentPeX,
      downloadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes),
      uploadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes * 1.2),
      natUpnp: 'permanent',
      torrentPort: settings.torrentPort,
      dhtPort: settings.dhtPort,
      maxConns: settings.maxConns,
      peerId
    }
    this[client] = new WebTorrent(this[opts])
    this[client].on('error', console.error)
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
  }

  updateSettings (settings: TorrentSettings & { path: string }) {
    this[client].throttleDownload(Math.round(settings.torrentSpeed * megaBitsToBytes))
    this[client].throttleUpload(Math.round(settings.torrentSpeed * megaBitsToBytes * 1.2))
    this[opts] = {
      dht: !settings.torrentDHT,
      utPex: !settings.torrentPeX,
      downloadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes),
      uploadLimit: Math.round(settings.torrentSpeed * megaBitsToBytes * 1.2),
      natUpnp: 'permanent',
      torrentPort: settings.torrentPort,
      dhtPort: settings.dhtPort,
      maxConns: settings.maxConns,
      peerId
    }
    this[path] = settings.path || this[tmp]
    this[store] = new Store(this[path])
    this.streamed = settings.torrentStreamedDownload
    this.persist = settings.torrentPersist
    // this[doh]?.destroy()
    // try {
    //   if (settings.doh) this[doh] = new DoHResolver(settings.doh)
    // } catch (error) {
    //   console.error(error)
    // }
  }

  cleanupLast: undefined | (() => Promise<void>) = undefined

  // WARN: ONLY CALL THIS DURING SETUP!!!
  async checkIncomingConnections (torrentPort: number): Promise<boolean> {
    await this.cleanupLast?.()
    await new Promise(resolve => this[client].destroy(resolve))

    return await new Promise(resolve => {
      const checkClient = new WebTorrent({ torrentPort, natUpnp: 'permanent', peerId })
      const torrent = checkClient.add(
        atob('bWFnbmV0Oj94dD11cm46YnRpaDpkZDgyNTVlY2RjN2NhNTVmYjBiYmY4MTMyM2Q4NzA2MmRiMWY2ZDFjJmRuPUJpZytCdWNrK0J1bm55JnRyPXVkcCUzQSUyRiUyRmV4cGxvZGllLm9yZyUzQTY5NjkmdHI9dWRwJTNBJTJGJTJGdHJhY2tlci5jb3BwZXJzdXJmZXIudGslM0E2OTY5JnRyPXVkcCUzQSUyRiUyRnRyYWNrZXIuZW1waXJlLWpzLnVzJTNBMTMzNyZ0cj11ZHAlM0ElMkYlMkZ0cmFja2VyLmxlZWNoZXJzLXBhcmFkaXNlLm9yZyUzQTY5NjkmdHI9dWRwJTNBJTJGJTJGdHJhY2tlci5vcGVudHJhY2tyLm9yZyUzQTEzMzc='),
        { store: MemoryChunkStore }
      )
      // patching library to not create outgoing connections
      torrent._drain = () => undefined
      checkClient.on('error', console.error)
      const cleanup = this.cleanupLast = async (val = false) => {
        if (checkClient.destroyed) return
        await new Promise(resolve => checkClient.destroy(resolve))
        this[client] = new WebTorrent(this[opts])
        this[store] = new Store(this[path])
        this[client].on('error', console.error)
        this[server] = this[client].createServer({}, 'node').listen(0)
        resolve(val)
      }

      setTimeout(() => cleanup(), 60_000).unref()
      torrent.on('wire', () => cleanup(true))
    })
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

  async toInfoHash (torrentId: string) {
    let parsed: { infoHash: string } | undefined

    // @ts-expect-error bad typedefs
    // eslint-disable-next-line @typescript-eslint/await-thenable
    try { parsed = await parseTorrent(torrentId) } catch (err) {}
    return parsed?.infoHash
  }

  async playTorrent (id: string, mediaID: number, episode: number): Promise<TorrentFile[]> {
    const existing = await this[client].get(id)

    // race condition hell, if some1 added a torrent Z in path A, switched torrents, then changed to path B and played torrent Z again, and that torrent was cached in path B, we want that cache data before its removed by non-existing check
    const storeData = !existing ? await this[store].get(await this.toInfoHash(id)) : undefined

    if (!existing && this[client].torrents[0]) {
      const hash = this[client].torrents[0].infoHash
      // @ts-expect-error bad typedefs
      await this[client].remove(this[client].torrents[0], { destroyStore: !this.persist })
      if (!this.persist) await this[store].delete(hash)
    }

    const torrent: Torrent = existing ?? this[client].add(storeData?.torrent ?? id, {
      path: this[path],
      announce: ANNOUNCE,
      bitfield: storeData?.bencoded._bitfield,
      deselect: this.streamed
    })
    // torrent._drain = () => undefined

    if (!torrent.ready) await new Promise(resolve => torrent.once('ready', resolve))

    this.attachments.register(torrent.files, torrent.infoHash)

    const baseInfo = structTorrent({
      // @ts-expect-error bad typedefs
      info: torrent.info,
      announce: torrent.announce,
      private: torrent.private,
      urlList: torrent.urlList,
      bitfield: torrent.bitfield!.buffer,
      date: Date.now(),
      mediaID,
      episode
    })

    // store might be updated during the torrent download, but the torrent won't be magically moved, so we want to persist this cached store location
    const cachedStore = this[store]
    const savebitfield = () => cachedStore.set(torrent.infoHash, baseInfo)
    const finish = () => {
      savebitfield()
      clearInterval(interval)
    }

    const interval = setInterval(savebitfield, 1000 * 20).unref()

    // so the cached() function is populated and can be called instantly after the torrent is added
    await savebitfield()

    torrent.on('done', finish)
    torrent.on('close', finish)

    return torrent.files.map(({ name, type, size, path, streamURL }, id) => ({
      hash: torrent.infoHash, name, type, size, path, id, url: 'http://localhost:' + (this[server].address() as AddressInfo).port + streamURL
    }))
  }

  async rescanTorrents (hashes: string[]) {
    const tmpclient = new WebTorrent({
      dht: false,
      utPex: false,
      downloadLimit: 0,
      maxConns: 0,
      peerId,
      tracker: {},
      natUpnp: false,
      natPmp: false,
      utp: false
    })

    const promises: Array<Promise<void>> = []

    const cachedStore = this[store]

    const currentHash = this[client].torrents[0]?.infoHash

    for (const hash of hashes) {
      if (hash === currentHash) continue
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
      tracker: {},
      natUpnp: false,
      natPmp: false,
      utp: false
    })

    const cachedStore = this[store]

    const promises: Array<Promise<void>> = []

    const currentHash = this[client].torrents[0]?.infoHash

    for (const hash of hashes) {
      if (hash === currentHash) continue
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

  async createNZBWebSeed (id: string, url: string, domain: string, port: number, login: string, password: string, group: string, poolSize: number) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')

    await createNZB(torrent, url, domain, port, login, password, group, poolSize)
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

      return {
        ip: wire.remoteAddress.replace(/^::ffff:/, '') + ':' + wire.remotePort,
        seeder: wire.isSeeder,
        client: `${parsed.client} ${parsed.version ?? '?'}`,
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

  async destroy () {
    await Promise.all([
      attachments.destroy(),
      new Promise(resolve => this[client].destroy(resolve)),
      new Promise(resolve => tracker.destroy(resolve))
    ])
    // this[doh]?.destroy()
    exit()
  }
}
