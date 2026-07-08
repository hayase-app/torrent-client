/* eslint-disable @typescript-eslint/no-unnecessary-condition */
/* eslint-disable @typescript-eslint/no-unsafe-declaration-merging */
import { gunzip } from 'node:zlib'

import { fromPost } from '@thaunknown/yencode'
import BitField from 'bitfield'
import Wire from 'bittorrent-protocol'
import fetch from 'cross-fetch-ponyfill'
import debugFactory from 'debug'
import ltDontHave from 'lt_donthave'
import { NNTPFile } from 'nzb-file/src'
import { Pool } from 'nzb-file/src/pool'
import parse from 'nzb-parser'
import { hash, concat } from 'uint8-util'
import Peer from 'webtorrent/lib/peer.js'

import type EventEmitter from 'node:events'
import type Torrent from 'webtorrent/lib/torrent.js'

const debug = debugFactory('webtorrent:nzbwebseed')

async function urlToContents (url: string) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`Failed to fetch NZB: ${res.statusText}`)

  if (url.endsWith('.nzb.gz') || res.headers.get('content-type') === 'application/gzip') {
    const buffer = await res.arrayBuffer()
    return await new Promise<string>((resolve, reject) => gunzip(Buffer.from(buffer), (err, result) => {
      if (err) return reject(err)
      resolve(result.toString('utf-8'))
    }))
  }
  return await res.text()
}

type TorrentFile = File & EventEmitter & { _startPiece: number, _endPiece: number }

export class NZBManager {
  pool

  constructor (domain: string, port: number, login: string, password: string, _poolSize: number) {
    this.pool = new Pool(login, password, 'alt.binaries.multimedia.anime.highspeed', domain, port, _poolSize)
  }

  addedNZBs = new Set<string>()

  async addNZBPeers (torrent: Torrent, url: string) {
    if (this.addedNZBs.has(url + torrent.infoHash)) return
    this.addedNZBs.add(url + torrent.infoHash)

    const { files } = parse(await urlToContents(url))
    await this.pool.ready
    if (torrent.destroyed || torrent.done) return

    const torrentFileToNZBFileMap = new Map<TorrentFile, NNTPFile>()

    const fileList: NNTPFile[] = await Promise.all(files.map(async ({ name, segments, datetime }) => {
      const { data } = await this.pool.body(`<${segments[0]?.messageId}>`)
      const { props } = fromPost(Buffer.from(data))
      return new NNTPFile({ name, size: parseInt(props!.begin.size), segments, segmentSize: parseInt(props!.part.end), lastModifiedDate: datetime, pool: this.pool })
    }))

    if (torrent.destroyed || torrent.done) return

    // find files by name or path, of file size if no other files match
    for (const file of torrent.files) {
      const nzbFile = fileList.find(f => f.name === file.name || f.name === file.path)
      if (nzbFile) {
        torrentFileToNZBFileMap.set(file, nzbFile)
      } else {
        const sizeMatch = fileList.filter(f => f.size === file.length)
        if (sizeMatch.length === 1) {
          torrentFileToNZBFileMap.set(file, sizeMatch[0]!)
        }
      }
    }

    for (const wire of this.registeredTorrents.get(torrent.infoHash) ?? []) {
      wire._mergeFileList(torrentFileToNZBFileMap)
    }
  }

  registeredTorrents = new Map<string, NZBWebSeed[]>()
  async register (torrent: Torrent) {
    if (this.registeredTorrents.has(torrent.infoHash)) return

    if (!torrent.ready) await new Promise(resolve => torrent.once('ready', resolve))
    await this.pool.ready
    if (torrent.destroyed || torrent.done) return

    const poolSize = this.pool.pool.size
    const domain = this.pool.pool.values().next().value?.host
    if (!domain) return

    const peers: NZBWebSeed[] = []
    for (let i = 0; i < poolSize; i++) {
      const id = domain + '-' + (i + 1)
      const conn = new NZBWebSeed(torrent, id)
      const newPeer = Peer.createWebSeedPeer(conn, id, torrent, torrent.client.throttleGroups)
      // @ts-expect-error non-standard hacky, dont care
      newPeer.wire!.domain = domain

      torrent._registerPeer(newPeer)
      peers.push(conn)

      torrent.emit('peer', id)
    }

    this.registeredTorrents.set(torrent.infoHash, peers)
    torrent.once('destroyed', () => {
      this.registeredTorrents.delete(torrent.infoHash)
    })
  }

  destroy () {
    return this.pool.destroy()
  }
}

interface NZBWebSeed extends EventEmitter {
  destroyed: boolean
}

class NZBWebSeed extends Wire {
  connId
  _torrent
  _files = new Map<TorrentFile, NNTPFile[]>()
  lt_donthave!: InstanceType<ReturnType<typeof ltDontHave>>
  _bitfield

  constructor (torrent: Torrent, id: string) {
    super()

    this.connId = id
    this._torrent = torrent

    this.setKeepAlive(true)

    this.use(ltDontHave())
    const numPieces = torrent.pieces.length
    this._bitfield = new BitField(numPieces)
    for (let i = 0; i <= numPieces; i++) {
      this._bitfield.set(i, false)
    }

    this.once('handshake', async (infoHash, peerId) => {
      const hex = await hash(this.connId, 'hex') // Used as the peerId for this fake remote peer
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
        // Cancel all in progress requests for this piece
        this.lt_donthave.donthave(pieceIndex)

        queueMicrotask(() => callback(error))
      }
    })
  }

  _mergeFileList (map: Map<TorrentFile, NNTPFile>) {
    for (const [file, nntpfile] of map) {
      if (!this._files.has(file)) {
        this._files.set(file, [])
      }
      this._files.get(file)!.push(nntpfile)

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
      nntpfiles: NNTPFile[]
      start: number
      end: number
    }> = []
    if (files.length <= 1) {
      const nntpfiles = this._files.values().next().value
      if (nntpfiles) {
        requests.push({
          nntpfiles,
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
        const nntpfiles = this._files.get(requestedFile)
        if (!nntpfiles) throw new Error('Could not find file corresponding to web seed range request')
        const fileEnd = requestedFile.offset + requestedFile.length - 1
        requests.push({
          nntpfiles,
          start: Math.max(rangeStart - requestedFile.offset, 0),
          end: Math.min(fileEnd, rangeEnd - requestedFile.offset)
        })
      }
    }

    if (!requests.length) {
      throw new Error('Could not find file corresponding to web seed range request')
    }

    const chunks = await Promise.all(requests.map(async ({ start, end, nntpfiles }) => {
      debug(
        'Requesting pieceIndex=%d offset=%d length=%d start=%d end=%d',
        pieceIndex, offset, length, start, end
      )

      for (const nntpfile of nntpfiles) {
        try {
          debug('Trying file %s (size %d)', nntpfile.name, nntpfile.size)
          const data = await nntpfile.slice(start, end + 1).bytes()

          debug('Got data of length %d', data.length)

          return data
        } catch (error) {
          debug('Error requesting file %s: %s', nntpfile.name, error)
        }
      }
      throw new Error('All files corresponding to web seed range request failed')
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
