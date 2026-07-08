/* eslint-disable @typescript-eslint/no-unsafe-declaration-merging */
import { Agent as HttpAgent } from 'node:http'
import { Agent as HttpsAgent } from 'node:https'

import BitField from 'bitfield'
import Wire from 'bittorrent-protocol'
import fetch from 'cross-fetch-ponyfill'
import debugFactory from 'debug'
import ltDontHave from 'lt_donthave'
import { hash, concat } from 'uint8-util'
import Peer from 'webtorrent/lib/peer.js'

import type EventEmitter from 'node:events'
import type { Agent as AgentType } from 'undici-types'
import type Torrent from 'webtorrent/lib/torrent.js'

const debug = debugFactory('webtorrent:httpwebseed')

const httpAgent = new HttpAgent({ keepAlive: true })
const httpsAgent = new HttpsAgent({ keepAlive: true })

const globalDispatcher = Symbol.for('undici.globalDispatcher.1')
const withDispatcher = globalThis as unknown as { [globalDispatcher]?: AgentType }
const Agent = withDispatcher[globalDispatcher]?.constructor as typeof AgentType | undefined

let undiciAgent: AgentType
try {
  if (Agent) undiciAgent = new Agent({ allowH2: true })
} catch {}

async function fetchRange (url: string, start: number, end: number, authorization?: string): Promise<Uint8Array> {
  const headers: Record<string, string> = {
    range: `bytes=${start}-${end}`,
    'cache-control': 'no-store'
  }
  if (authorization) headers.authorization = authorization

  const isHttps = new URL(url).protocol === 'https:'

  const res = await fetch(url, {
    method: 'GET',
    headers,
    signal: AbortSignal.timeout(60_000),
    // @ts-expect-error support node-fetch AND undici-fetch
    agent: isHttps ? httpsAgent : httpAgent,
    dispatcher: undiciAgent
  })

  if (!res.ok) {
    if (res.status === 416) throw new Error('Range not satisfiable')
    throw new Error(`HTTP ${res.status}`)
  }

  return new Uint8Array(await res.arrayBuffer())
}

type TorrentFile = File & EventEmitter & { _startPiece: number, _endPiece: number }

export class HTTPManager {
  registeredTorrents = new Map<string, HTTPWebSeed[]>()

  async addHTTPPeers (torrent: Torrent, url: string, authorization?: string, fileIndex?: number) {
    if (torrent.destroyed || torrent.done) return
    if (!torrent.ready) await new Promise(resolve => torrent.once('ready', resolve))
    if (torrent.destroyed || torrent.done) return

    const files = torrent.files
    const map = new Map<TorrentFile, Array<{ url: string, authorization?: string }>>()

    if (files.length === 1) {
      map.set(files[0], [{ url, authorization }])
    } else if (fileIndex !== undefined && fileIndex >= 0 && fileIndex < files.length) {
      map.set(files[fileIndex], [{ url, authorization }])
    } else {
      const name = decodeURIComponent(url.split('/').pop() ?? url)
      const match = files.find(f => f.name === name || f.path === name)
      if (match) {
        map.set(match, [{ url, authorization }])
      } else {
        // Full-torrent URL – map to all files
        for (const file of files) {
          map.set(file, [{ url, authorization }])
        }
      }
    }

    const wires = this.registeredTorrents.get(torrent.infoHash)
    if (wires) {
      for (const wire of wires) {
        wire._mergeFileList(map)
      }
      return
    }

    // register
    const peers: HTTPWebSeed[] = []
    for (let i = 0; i < 2; i++) {
      const id = await hash(url + (authorization ?? '') + i, 'hex')
      const conn = new HTTPWebSeed(torrent)
      const newPeer = Peer.createWebSeedPeer(conn, id, torrent, torrent.client.throttleGroups)
      // @ts-expect-error non-standard hacky, dont care
      newPeer.wire!.domain = new URL(url).hostname

      torrent._registerPeer(newPeer)
      peers.push(conn)

      torrent.emit('peer', id)

      conn._mergeFileList(map)
    }
    this.registeredTorrents.set(torrent.infoHash, peers)
    torrent.once('destroyed', () => {
      this.registeredTorrents.delete(torrent.infoHash)
    })
  }

  async destroy () {
    for (const seeds of this.registeredTorrents.values()) {
      for (const seed of seeds) {
        seed.destroy()
      }
    }
    this.registeredTorrents.clear()
  }
}

interface HTTPWebSeed extends EventEmitter {
  destroyed: boolean
}

class HTTPWebSeed extends Wire {
  connId
  _torrent
  _files = new Map<TorrentFile, Array<{ url: string, authorization?: string }>>()
  lt_donthave!: InstanceType<ReturnType<typeof ltDontHave>>
  _bitfield

  constructor (torrent: Torrent) {
    super()

    this.connId = torrent.infoHash
    this._torrent = torrent

    this.setKeepAlive(true)

    this.use(ltDontHave())
    const numPieces = torrent.pieces.length
    this._bitfield = new BitField(numPieces)
    for (let i = 0; i <= numPieces; i++) {
      this._bitfield.set(i, false)
    }

    this.once('handshake', async (infoHash, peerId) => {
      const hex = await hash(this.connId, 'hex')
      if (this.destroyed) return
      this.handshake(infoHash, hex, {})

      this.bitfield(this._bitfield)
    })

    this.once('interested', () => {
      debug('interested')
      this.unchoke()
    })

    this.on('uninterested', () => { debug('uninterested') })
    this.on('choke', () => { debug('choke') })
    this.on('unchoke', () => { debug('unchoke') })
    this.on('bitfield', () => { debug('bitfield') })
    this.lt_donthave.on('donthave', () => { debug('donthave') })

    this.on('request', async (pieceIndex, offset, length, callback) => {
      debug('request pieceIndex=%d offset=%d length=%d', pieceIndex, offset, length)
      try {
        const data = await this.request(pieceIndex, offset, length)
        queueMicrotask(() => callback(null, data))
      } catch (error) {
        this.lt_donthave.donthave(pieceIndex)
        queueMicrotask(() => callback(error))
      }
    })
  }

  _mergeFileList (map: Map<TorrentFile, Array<{ url: string, authorization?: string }>>) {
    for (const [file, urlConfigs] of map) {
      if (!this._files.has(file)) {
        this._files.set(file, [])
      }
      this._files.get(file)!.push(...urlConfigs)

      for (let i = file._startPiece; i <= file._endPiece; ++i) {
        this._bitfield.set(i, true)
      }
    }

    this.bitfield(this._bitfield)
  }

  async request (pieceIndex: number, offset: number, length: number) {
    // @ts-expect-error incorrect infer
    const pieceOffset = pieceIndex * this._torrent.pieceLength
    const rangeStart = pieceOffset + offset /* offset within whole torrent */
    const rangeEnd = rangeStart + length - 1

    const files = this._torrent.files
    const requests: Array<{
      urlConfigs: Array<{ url: string, authorization?: string }>
      start: number
      end: number
    }> = []

    if (files.length <= 1) {
      const urlConfigs = this._files.values().next().value
      if (urlConfigs) {
        requests.push({
          urlConfigs,
          start: rangeStart,
          end: rangeEnd
        })
      }
    } else {
      const requestedFiles = files.filter(file => file.offset <= rangeEnd && (file.offset + file.length) > rangeStart)
      if (requestedFiles.length < 1) {
        throw new Error('Could not find file corresponding to web seed range request')
      }

      for (const requestedFile of requestedFiles) {
        const urlConfigs = this._files.get(requestedFile)
        if (!urlConfigs) throw new Error('Could not find URL for file')
        const fileEnd = requestedFile.offset + requestedFile.length - 1
        requests.push({
          urlConfigs,
          start: Math.max(rangeStart - requestedFile.offset, 0),
          end: Math.min(fileEnd, rangeEnd - requestedFile.offset)
        })
      }
    }

    if (!requests.length) {
      throw new Error('Could not find file corresponding to web seed range request')
    }

    const chunks = await Promise.all(requests.map(async ({ start, end, urlConfigs }) => {
      debug(
        'Requesting pieceIndex=%d offset=%d length=%d start=%d end=%d',
        pieceIndex, offset, length, start, end
      )

      for (const { url, authorization } of urlConfigs) {
        try {
          const data = await fetchRange(url, start, end, authorization)
          debug('Got data of length %d', data.length)
          return data
        } catch (error) {
          debug('Error requesting %s: %s', url, error)
        }
      }
      throw new Error('All URLs corresponding to web seed range request failed')
    }))

    return chunks.length === 1 ? chunks[0]! : concat(chunks)
  }

  destroy () {
    super.destroy()
    // @ts-expect-error gc safety
    this._torrent = null
    return this
  }
}
