import { once } from 'node:events'
import { exit } from 'node:process'

import debug from 'debug'
import networkAddress from 'network-address'
import { remote } from 'parse-torrent'
import WebTorrent from 'webtorrent'

import { ChromeCasts } from './chromecast/index.ts'
import { ACTIVE_STORE_CACHE_SLOTS, BACKGROUND_STORE_CACHE_SLOTS, DHT_BOOTSTRAP, megaBitsToBytes, peerId } from './common/constants.ts'
import { DLNAs } from './dlna/index.ts'
import attachments from './ebml/attachments.ts'
import { checkAvailableSpace, verifyDirectoryPermissions } from './filesystem/index.ts'
import { Store, structTorrent } from './filesystem/store.ts'
import DoHResolver from './network/doh.ts'
import { checkIncomingConnections } from './network/index.ts'
import { getFileInfo, getLibraryEntry, getPeerInfo, getProtocolStatus, getStats } from './torrent/info.ts'
import { ANNOUNCE, getTrackers, tracker, scrape, type ScrapeResponse } from './tracker/index.ts'
import { HTTPManager } from './webseed/http.ts'
import { NZBManager } from './webseed/nzb.ts'

import type { PROVIDERS } from './network/doh.ts'
import type { MediaInformation } from 'chromecast-caf-receiver/cast.framework.messages'
import type { LibraryEntry, TorrentFile, TorrentInfo, ClientSettings } from 'native'
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import type Torrent from 'webtorrent/lib/torrent.js'

const client = Symbol('client')
const server = Symbol('server')
const store = Symbol('store')
const path = Symbol('path')
const opts = Symbol('opts')
const tmp = Symbol('tmp')
const doh = Symbol('doh')
const nzb = Symbol('nzb')
const http = Symbol('http')

process.on('uncaughtException', err => console.error(err))
process.on('unhandledRejection', err => console.error(err))

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
  checkIncomingConnections (testPort: number): Promise<boolean> {
    return checkIncomingConnections(testPort)
  }

  checkAvailableSpace () {
    return checkAvailableSpace(this[path])
  }

  scrape (infoHashes: string[]): Promise<ScrapeResponse[]> {
    return scrape(infoHashes)
  }

  async toInfoHash (torrentId: string | ArrayBufferView) {
    let parsed: { infoHash: string } | undefined

    try { parsed = await new Promise(resolve => remote(torrentId, (_err: Error | null, val: { infoHash: string }) => resolve(val))) } catch (err) {}
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

    const activeHashes = new Set(this.sessions.values())

    for (const hash of hashes) {
      if (activeHashes.has(hash)) continue
      promises.push(
        (async () => {
          if (await this[client].get(hash)) {
            await new Promise(resolve => this[client].remove(hash, { destroyStore: true }, resolve))
            await cachedStore.delete(hash)
            return
          }

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

  async removeBackgroundTorrents (hashes: string[]) {
    const activeHashes = new Set(this.sessions.values())

    await Promise.allSettled(hashes.map(async hash => {
      if (activeHashes.has(hash)) return

      const entry = this.torrentState.get(hash)
      if (!entry?.background) return

      if (entry.torrent.destroyed) {
        return this.torrentState.delete(hash)
      }

      const { torrent, mediaID, episode } = entry

      await new Promise(resolve => this[client].remove(torrent, { destroyStore: !this.persist }, resolve))

      if (this.persist) {
        await this[store].set(hash, structTorrent({
          // @ts-expect-error bad typedefs
          info: torrent.info,
          announce: torrent.announce,
          private: torrent.private,
          urlList: torrent.urlList,
          bitfield: torrent.bitfield!.buffer,
          date: Date.now(),
          mediaID,
          episode,
          background: false
        }))
      } else {
        await this[store].delete(hash)
      }
    }))
  }

  async cached () {
    return await this[store].list()
  }

  // TODO: use https://www.npmjs.com/package/comlink-async-generator?activeTab=code
  async library () {
    const torrents: LibraryEntry[] = []
    for await (const { torrent, bencoded } of this[store].entries()) {
      torrents.push(getLibraryEntry(torrent, bencoded))
    }
    return torrents
  }

  async trackers (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')

    return await getTrackers(torrent)
  }

  errors (cb: (errors: Error) => void) {
    this[client].on('error', err => cb(err))
    this[client].on('error', err => console.error(err))
    process.on('uncaughtException', err => cb(err))
  }

  debug (levels: string) {
    debug.disable()
    if (levels) debug.enable(levels)
  }

  torrents () {
    return this[client].torrents.map(t => getStats(t))
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
    return getStats(torrent)
  }

  async peerInfo (id: string) {
    const torrent = await this[client].get(id)

    if (!torrent) throw new Error('Torrent not found')
    return getPeerInfo(torrent)
  }

  verifyDirectoryPermissions (path: string) {
    return verifyDirectoryPermissions(path, this[tmp])
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

    savebitfield()

    if (torrent.done) return

    const interval = setInterval(savebitfield, 1000 * 20).unref()

    torrent.on('done', () => {
      savebitfield()
      clearInterval(interval)
    })
    torrent.once('close', () => clearInterval(interval))
  }

  updateStoreCache (torrent: Torrent, active: boolean) {
    if (torrent.destroyed) return

    const { store } = torrent as unknown as {
      store?: { store?: { cache?: { max: number, length: number, evict: () => void } } } | null
    }

    const slots = active ? ACTIVE_STORE_CACHE_SLOTS : BACKGROUND_STORE_CACHE_SLOTS

    const cache = store?.store?.cache
    if (!cache) return

    cache.max = slots
    while (cache.length > slots) cache.evict()
  }

  updateTorrentPriority (infoHash?: string) {
    if (!infoHash) return
    const entry = this.torrentState.get(infoHash)
    if (!entry) return

    const { torrent, background } = entry
    if (torrent.destroyed) return

    const sessionCount = [...this.sessions.values()].filter(h => h === infoHash).length
    const downloadLimit = this[opts].downloadLimit as number

    this.updateStoreCache(torrent, sessionCount > 0)

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
      deselect,
      storeCacheSlots: background ? BACKGROUND_STORE_CACHE_SLOTS : ACTIVE_STORE_CACHE_SLOTS
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

    this.updateStoreCache(torrent, !background)

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
    return this[client].torrents.map(t => getStats(t))
  }

  async fileInfo (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')
    return getFileInfo(torrent)
  }

  async protocolStatus (id: string) {
    const torrent = await this[client].get(id)
    if (!torrent) throw new Error('Torrent not found')
    return getProtocolStatus(this[client], torrent, this.persist)
  }

  makeStats (torrent: Torrent): TorrentInfo {
    return getStats(torrent)
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
