import { readFile, writeFile, unlink, mkdir, readdir } from 'node:fs/promises'
import { join } from 'node:path'

import bencode from 'bencode'
import parseTorrent from 'parse-torrent'
import { text2arr } from 'uint8-util'

export interface TorrentMetadata {
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

export interface TorrentData {
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

export function structTorrent ({ info, urlList, bitfield, announce, private: priv, mediaID, episode, date, background }: TorrentMetadata) {
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

export class Store {
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
