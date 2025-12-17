/* eslint-disable @typescript-eslint/no-unsafe-declaration-merging */
import { Worker } from 'node:worker_threads'

import { wrap } from 'abslink'
import BitField from 'bitfield'
import Wire from 'bittorrent-protocol'
import debugFactory from 'debug'
import ltDontHave from 'lt_donthave'
import { hash } from 'uint8-util'
import Peer from 'webtorrent/lib/peer.js'

import type NZBWorker from './worker.ts'
import type { Remote } from 'abslink'
import type EventEmitter from 'node:events'
import type Torrent from 'webtorrent/lib/torrent.js'

const debug = debugFactory('webtorrent:nzbwebseed')

export async function createNZB (torrent: Torrent, url: string, domain: string, port: number, login: string, password: string, _poolSize: number) {
  if (!torrent.ready) await new Promise(resolve => torrent.once('ready', resolve))
  if (torrent.destroyed || torrent.done) return

  const worker = new Worker(new URL('./worker.ts', import.meta.url))

  // @ts-expect-error incorrect infer
  const pieceLength: number = torrent.pieceLength

  const nzbWorker = await new (wrap<typeof NZBWorker>(worker))(pieceLength, torrent.files.map(file => ({
    offset: file.offset,
    length: file.length,
    name: file.name,
    path: file.path,
    size: file.size
  })))

  const poolSize = await nzbWorker.createNZB(url, domain, port, login, password, _poolSize)

  if (torrent.destroyed) return await nzbWorker.destroy()
  torrent.once('close', () => nzbWorker.destroy())

  for (let i = 0; i < poolSize; i++) {
    const id = domain + '-' + (i + 1)
    const conn = new NZBWebSeed(torrent, id, nzbWorker)
    const newPeer = Peer.createWebSeedPeer(conn, id, torrent, torrent.client.throttleGroups)
    // @ts-expect-error non-standard hacky, dont care
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
  lt_donthave!: InstanceType<ReturnType<typeof ltDontHave>>
  worker
  constructor (torrent: Torrent, id: string, worker: Remote<InstanceType<typeof NZBWorker>>) {
    super()

    this.connId = id
    this._torrent = torrent
    this.worker = worker

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
        const data = await worker.makeRequest(pieceIndex, offset, length)
        queueMicrotask(() => callback(null, data))
      } catch (error) {
        // Cancel all in progress requests for this piece
        this.lt_donthave.donthave(pieceIndex)

        queueMicrotask(() => callback(error))
      }
    })
  }

  destroy () {
    super.destroy()
    // @ts-expect-error gc safety
    this._torrent = null
    this.worker.destroy()
    return this
  }
}
