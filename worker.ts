import { parentPort } from 'node:worker_threads'
import zlib from 'node:zlib'

import { expose } from 'abslink'
import debugFactory from 'debug'
import fromNZB, { type NNTPFile } from 'nzb-file/src'
import { concat } from 'uint8-util'

import type { Pool } from 'nzb-file/src/pool'

const debug = debugFactory('webtorrent:nzbwebseed')
export default expose(class NZBWorker {
  torrentFiles
  pieceLength
  files
  pool?: Pool

  constructor (pieceLength: number, torrentFiles: Array<{offset: number, length: number, name: string, path: string, size: number}>) {
    this.pieceLength = pieceLength
    this.torrentFiles = torrentFiles

    this.files = new Map<number, NNTPFile>()
  }

  async createNZB (url: string, domain: string, port: number, login: string, password: string, _poolSize: number) {
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Failed to fetch NZB: ${res.statusText}`)

    let contents: string
    if (url.endsWith('.nzb.gz') || res.headers.get('content-type') === 'application/gzip') {
      const buffer = await res.arrayBuffer()
      contents = await new Promise<string>((resolve, reject) => zlib.gunzip(buffer, (err, result) => {
        if (err) return reject(err)
        resolve(result.toString('utf-8'))
      }))
    } else {
      contents = await res.text()
    }
    const { files, pool } = await fromNZB(contents, domain, port, login, password, 'alt.binaries.multimedia.anime.highspeed', _poolSize)

    this.pool = pool

    await pool.ready

    const poolSize = Math.ceil(pool.pool.size / 2)

    for (const file of this.torrentFiles) {
      const nzbFile = files.find(f => f.name === file.name || f.name === file.path)
      if (nzbFile) {
        this.files.set(file.offset, nzbFile)
      } else {
        const sizeMatch = files.filter(f => f.size === file.length)
        if (sizeMatch.length === 1) {
          this.files.set(file.offset, sizeMatch[0]!)
        }
      }
    }

    return poolSize
  }

  destroy () {
    return this.pool?.destroy()
  }

  async makeRequest (pieceIndex: number, offset: number, length: number) {
    const pieceOffset = pieceIndex * this.pieceLength
    const rangeStart = pieceOffset + offset /* offset within whole torrent */
    const rangeEnd = rangeStart + length - 1

    const files = this.torrentFiles
    const requests: Array<{
      nntpfile: NNTPFile
      start: number
      end: number
    }> = []
    if (files.length <= 1) {
      const nntpfile = this.files.get(0)
      if (nntpfile) {
        requests.push({
          nntpfile: this.files.get(0)!,
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
        const nntpfile = this.files.get(requestedFile.offset)
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
}, parentPort!)
