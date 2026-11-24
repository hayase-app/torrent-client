/* eslint-disable @typescript-eslint/no-unnecessary-condition */

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

import type { FileMeta } from 'nzb-parser/src/models'
import type File from 'webtorrent/lib/file'
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

    const filesByName = new Map<string, File>()
    for (const file of torrent.files) {
      filesByName.set(file.name, file)
      filesByName.set(file.path, file)
    }

    const torrentFileToNZBFileMap = new Map<File, NNTPFile>()

    // find files by name or path
    const namedFiles = await this.probe(files.filter(({ name }) => filesByName.has(name)))
    for (const nzbFile of namedFiles) {
      const file = filesByName.get(nzbFile.name)!
      // an nzb can have multiple entries with the same name, like a repost, so use the first one
      if (!torrentFileToNZBFileMap.has(file)) torrentFileToNZBFileMap.set(file, nzbFile)
    }

    // find the remaining files by size, every probe costs an article download, so only probe the other entries if files remain
    const remainingFiles = torrent.files.filter(file => !torrentFileToNZBFileMap.has(file))
    if (remainingFiles.length) {
      const otherFiles = await this.probe(files.filter(({ name }) => !filesByName.has(name)))

      // a size that multiple entries have does not identify a file
      const filesBySize = new Map<number, NNTPFile | undefined>()
      for (const nzbFile of otherFiles) {
        filesBySize.set(nzbFile.size, filesBySize.has(nzbFile.size) ? undefined : nzbFile)
      }
      for (const file of remainingFiles) {
        const nzbFile = filesBySize.get(file.length)
        if (nzbFile) torrentFileToNZBFileMap.set(file, nzbFile)
      }
    }

    if (torrent.destroyed || torrent.done) return

    for (const wire of this.registeredTorrents.get(torrent.infoHash) ?? []) {
      wire._mergeFileList(torrentFileToNZBFileMap)
    }
  }

  async probe (files: FileMeta[]) {
    const nzbFiles = await Promise.all(files.map(async ({ name, segments, datetime }) => {
      // a full segment gives the size and the segment size of the file, articles can be missing or from another upload, and bad ones come in runs,
      // so try segments spread over the file, except the last, shorter one
      for (const { messageId, number } of new Set([0, 0.25, 0.5, 0.75].map(at => segments[Math.floor(at * (segments.length - 1))]!))) {
        try {
          const { data } = await this.pool.body(`<${messageId}>`)
          const { begin, part } = fromPost(Buffer.from(data)).props!
          const segmentSize = parseInt(part.end) - parseInt(part.begin) + 1
          // an article from another upload won't be at the position of this segment
          if (parseInt(part.begin) === (number - 1) * segmentSize + 1) {
            return new NNTPFile({ name, size: parseInt(begin.size), segments, segmentSize, lastModifiedDate: datetime, pool: this.pool })
          }
        } catch (error) {
          debug('Failed to probe article %s of %s: %s', messageId, name, error)
        }
      }
    }))
    return nzbFiles.filter(nzbFile => nzbFile != null)
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
      const conn = new NZBWebSeed(torrent, id, peers)
      const newPeer = Peer.createWebSeedPeer(conn, id, torrent, torrent.throttleGroups, torrent.client.throttleGroups)
      // @ts-expect-error non-standard hacky, dont care
      newPeer.wire!.domain = domain
      // @ts-expect-error non-standard hacky, dont care
      newPeer.wire!.webSeedType = 'nntp'

      torrent._registerPeer(newPeer)
      peers.push(conn)

      torrent.emit('peer', id)
    }

    this.registeredTorrents.set(torrent.infoHash, peers)
    torrent.once('close', () => {
      this.registeredTorrents.delete(torrent.infoHash)
      for (const key of [...this.addedNZBs]) {
        if (key.endsWith(torrent.infoHash)) this.addedNZBs.delete(key)
      }
    })
  }

  destroy () {
    return this.pool.destroy()
  }
}

class NZBWebSeed extends Wire {
  connId
  _torrent
  _files = new Map<File, NNTPFile[]>()
  lt_donthave!: InstanceType<ReturnType<typeof ltDontHave>>
  _bitfield
  _peers

  constructor (torrent: Torrent, id: string, peers: NZBWebSeed[]) {
    super()

    this.connId = id
    this._torrent = torrent
    this._peers = peers

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
      this.handshake(infoHash as string, hex, {})

      this.bitfield(this._bitfield)
    })

    this.once('interested', () => {
      debug('interested')
      this.unchoke()
    })

    this.on('uninterested', () => debug('uninterested'))
    this.on('choke', () => debug('choke'))
    this.on('unchoke', () => debug('unchoke'))
    this.on('bitfield', () => debug('bitfield'))
    this.lt_donthave.on('donthave', () => debug('donthave'))

    this.on('request', async (pieceIndex, offset, length, callback) => {
      debug('request pieceIndex=%d offset=%d length=%d', pieceIndex, offset, length)
      try {
        const data = await this.request(pieceIndex as number, offset as number, length as number)
        // @ts-expect-error bad typedefs
        queueMicrotask(() => callback(null, data))
      } catch (error) {
        // Cancel all in progress requests for this piece, on all nntp peers, since they share the same articles
        for (const peer of this._peers) {
          // the next bitfield message must not offer this piece again
          peer._bitfield.set(pieceIndex as number, false)
          peer.lt_donthave.donthave(pieceIndex)
        }

        // @ts-expect-error bad typedefs
        queueMicrotask(() => callback(error))
      }
    })
  }

  _mergeFileList (map: Map<File, NNTPFile>) {
    for (const [file, nntpfile] of map) {
      if (!this._files.has(file)) {
        this._files.set(file, [])
      }
      this._files.get(file)!.push(nntpfile)

      for (let i = file._startPiece; i <= file._endPiece; ++i) {
        this._bitfield.set(i, true)
      }
    }

    if (this._handshakeSent) this.bitfield(this._bitfield)
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
