/* eslint-disable @typescript-eslint/no-unsafe-declaration-merging */
import zlib from 'node:zlib'

import BitField from 'bitfield'
import Wire from 'bittorrent-protocol'
import debugFactory from 'debug'
import ltDontHave from 'lt_donthave'
import fromNZB, { type NNTPFile } from 'nzb-file/src'
import { hash, concat } from 'uint8-util'
import Peer from 'webtorrent/lib/peer.js'

import type EventEmitter from 'node:events'
import type Torrent from 'webtorrent/lib/torrent.js'

const debug = debugFactory('webtorrent:nzbwebseed')

export async function createNZB (torrent: Torrent, url: string, domain: string, port: number, login: string, password: string, _poolSize: number) {
  if (!torrent.ready) await new Promise(resolve => torrent.once('ready', resolve))
  if (torrent.destroyed || torrent.done) return

  const res = await fetch(url)
  if (!res.ok) throw new Error(`Failed to fetch NZB: ${res.statusText}`)

  let contents: string
  if (url.endsWith('.nzb.gz') || res.headers.get('content-type') === 'application/gzip') {
    const buffer = await res.arrayBuffer()
    contents = await new Promise<string>((resolve, reject) => zlib.gunzip(Buffer.from(buffer), (err, result) => {
      if (err) return reject(err)
      resolve(result.toString('utf-8'))
    }))
  } else {
    contents = await res.text()
  }
  const { files, pool } = await fromNZB(contents, domain, port, login, password, 'alt.binaries.multimedia.anime.highspeed', _poolSize)

  if (torrent.destroyed) return await pool.destroy()
  torrent.once('close', () => pool.destroy())

  await pool.ready

  const poolSize = pool.pool.size

  const torrentFileToNZBFileMap = new Map<number, NNTPFile>()

  // find files by name or path, of file size if no other files match
  for (const file of torrent.files) {
    const nzbFile = files.find(f => f.name === file.name || f.name === file.path)
    if (nzbFile) {
      torrentFileToNZBFileMap.set(file.offset, nzbFile)
    } else {
      const sizeMatch = files.filter(f => f.size === file.length)
      if (sizeMatch.length === 1) {
        torrentFileToNZBFileMap.set(file.offset, sizeMatch[0]!)
      }
    }
  }

  for (let i = 0; i < poolSize; i++) {
    const id = domain + '-' + (i + 1)
    const conn = new NZBWebSeed(torrentFileToNZBFileMap, torrent, id)
    const newPeer = Peer.createWebSeedPeer(conn, id, torrent, torrent.client.throttleGroups)
    newPeer.wire!.domain = domain

    torrent._registerPeer(newPeer)

    torrent.emit('peer', id)
  }
}

interface NZBWebSeed extends EventEmitter {
  destroyed: boolean
}

class NZBWebSeed extends Wire {
  connId
  _torrent
  _files
  lt_donthave!: InstanceType<ReturnType<typeof ltDontHave>>
  constructor (files: Map<number, NNTPFile>, torrent: Torrent, id: string) {
    super()

    this._files = files
    this.connId = id
    this._torrent = torrent

    this.setKeepAlive(true)

    this.use(ltDontHave())

    this.once('handshake', async (infoHash, peerId) => {
      const hex = await hash(this.connId, 'hex') // Used as the peerId for this fake remote peer
      if (this.destroyed) return
      // @ts-expect-error incorrect infer
      this.handshake(infoHash, hex)

      const numPieces = this._torrent.pieces.length
      const bitfield = new BitField(numPieces)
      for (let i = 0; i <= numPieces; i++) {
        bitfield.set(i, true)
      }
      this.bitfield(bitfield)
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
        callback(null, data)
      } catch (error) {
        // Cancel all in progress requests for this piece
        this.lt_donthave.donthave(pieceIndex)

        callback(error)
      }
    })
  }

  async request (pieceIndex: number, offset: number, length: number) {
    // @ts-expect-error incorrect infer
    const pieceOffset = pieceIndex * this._torrent.pieceLength
    const rangeStart = pieceOffset + offset /* offset within whole torrent */
    const rangeEnd = rangeStart + length - 1

    const files = this._torrent.files
    const requests: Array<{
      nntpfile: NNTPFile
      start: number
      end: number
    }> = []
    if (files.length <= 1) {
      const nntpfile = this._files.get(0)
      if (nntpfile) {
        requests.push({
          nntpfile: this._files.get(0)!,
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
        const nntpfile = this._files.get(requestedFile.offset)
        if (!nntpfile) throw new Error('Could not find file corresponding to web seed range request')
        const fileEnd = requestedFile.offset + requestedFile.length - 1
        requests.push({
          nntpfile,
          start: Math.max(rangeStart - requestedFile.offset, 0),
          end: Math.min(fileEnd, rangeEnd - requestedFile.offset)
        })
      }
    }

    if (!requests.length) {
      throw new Error('Could not find file corresponding to web seed range request')
    }

    const chunks = await Promise.all(requests.map(async ({ start, end, nntpfile }) => {
      debug(
        'Requesting pieceIndex=%d offset=%d length=%d start=%d end=%d',
        pieceIndex, offset, length, start, end
      )

      const data = await nntpfile.slice(start, end + 1).bytes()

      debug('Got data of length %d', data.length)

      return data
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
