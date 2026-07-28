import { createServer } from 'node:http'

import networkAddress from 'network-address'

import Metadata from './metadata.ts'

import type File from 'webtorrent/lib/file'

export default new class Attachments {
  destroyed = false
  filemap = new Map<string, File>()
  metadatamap = new Map<File, Metadata>()
  server = createServer(async (req, res) => {
    try {
      const { pathname } = new URL(req.url!, 'http://localhost')
      const [hashid, number] = pathname.split('/').slice(1)
      if (!hashid || !number) throw new Error('Invalid request')

      const file = this.filemap.get(hashid)
      if (!file) throw new Error('File not found')

      const metadata = this.metadatamap.get(file)
      if (!metadata) throw new Error('Metadata not found')

      const attachment = (await metadata.getAttachments())[Number(number)]
      if (!attachment) throw new Error('Attachment not found')

      res.writeHead(200, { 'Content-Type': String(attachment.mimetype), 'Access-Control-Allow-Origin': '*' })
      res.end(attachment.data instanceof Buffer ? attachment.data : Buffer.from(''))
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }))
    }
  }).listen()

  _metadata (hash: string, id: number) {
    const file = this.filemap.get(hash + id)
    if (!file) return
    const meta = this.metadatamap.get(file)
    if (meta) return meta
    const metadata = new Metadata(file)
    this.metadatamap.set(file, metadata)
    return metadata
  }

  subtitle (hash: string, id: number, cb: (subtitle: { text: string, time: number, duration: number }, trackNumber: number) => void) {
    const metadata = this._metadata(hash, id)
    if (!metadata) throw new Error('File not found')
    metadata.removeAllListeners('subtitle')
    metadata.on('subtitle', (a, b) => cb(a, b))
  }

  register (files: File[], hash: string) {
    this.filemap.clear()
    files.forEach((file, id) => {
      // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
      if (file.name.endsWith('.mkv') || file.name.endsWith('.webm')) {
        this.filemap.set(hash + id, file)
        file.on('iterator', ({ iterator }: { iterator: AsyncIterable<Uint8Array> }, cb: (it: AsyncIterable<Uint8Array>) => void) => {
          if (this.destroyed) return cb(iterator)
          cb(this._metadata(hash, id)?.parseStream(iterator) ?? iterator)
        })
      }
    })
  }

  async attachments (hash: string, id: number) {
    const metadata = this._metadata(hash, id)
    if (!metadata) throw new Error('File not found')

    const lan = networkAddress()
    return (await metadata.getAttachments()).map(({ filename, mimetype }, number) => {
      const addr = this.server.address()
      if (!addr || typeof addr === 'string') throw new Error('Server not listening')
      const suffix = ':' + addr.port + '/' + hash + id + '/' + number
      return { filename, mimetype, id, url: 'http://localhost' + suffix, lan: 'http://' + lan + suffix }
    })
  }

  chapters (hash: string, id: number) {
    const metadata = this._metadata(hash, id)
    if (!metadata) throw new Error('File not found')
    return metadata.getChapters()
  }

  tracks (hash: string, id: number) {
    const metadata = this._metadata(hash, id)
    if (!metadata) throw new Error('File not found')
    return metadata.getTracks()
  }

  async destroy () {
    this.destroyed = true
    await new Promise(resolve => this.server.close(resolve))
  }
}()
