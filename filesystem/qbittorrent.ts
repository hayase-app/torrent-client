import { access, copyFile, mkdir, readdir, readFile, rename, unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { basename, dirname, extname, join, relative } from 'node:path'
import { env, platform } from 'node:process'

import bencode from 'bencode'
import BitField from 'bitfield'
import parseTorrent from 'parse-torrent'
import { arr2text } from 'uint8-util'

import { getLibraryEntry } from '../torrent/info.ts'

import { checkAvailableSpace } from './index.ts'
import { structTorrent } from './store.ts'

import type { Store } from './store.ts'
import type { TorrentInfo } from 'native'

interface ResumeData {
  pieces: Uint8Array
  save_path: Uint8Array
  added_time: number
  mapped_files?: Uint8Array[]
  trackers?: Uint8Array[][]
  'url-list'?: Uint8Array[]
}

const dataFolders: Record<string, string | undefined> = {
  win32: env.LOCALAPPDATA,
  darwin: join(homedir(), 'Library', 'Application Support')
}

const backupFolder = join(dataFolders[platform] ?? env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share'), 'qBittorrent', 'BT_backup')

async function list () {
  try {
    const names = await readdir(backupFolder)
    return names.filter(name => extname(name) === '.fastresume').map(name => basename(name, '.fastresume'))
  } catch {
    return []
  }
}

async function load (hash: string) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/await-thenable
  const torrent: any = await parseTorrent(await readFile(join(backupFolder, hash + '.torrent')))
  if (torrent.infoHash !== hash) throw new Error(`${hash} has no v1 info hash`)

  // @ts-expect-error bad typedefs
  const resume = bencode.decode(await readFile(join(backupFolder, hash + '.fastresume'))) as ResumeData

  const bitfield = new BitField(resume.pieces.length)
  for (let index = 0; index < resume.pieces.length; ++index) {
    if (resume.pieces[index]! & 1) bitfield.set(index)
  }

  const data = structTorrent({
    info: torrent.info,
    announce: resume.trackers?.flat().map(url => arr2text(url)),
    urlList: resume['url-list']?.map(url => arr2text(url)),
    private: torrent.private,
    bitfield: bitfield.buffer,
    date: resume.added_time * 1000
  })

  return { torrent, resume, data }
}

export async function qbittorrentLibrary () {
  const torrents: TorrentInfo[] = []
  for (const hash of await list()) {
    try {
      const { torrent, data } = await load(hash)
      const { name, progress, size } = getLibraryEntry(torrent, data)
      torrents.push({
        hash,
        name,
        progress,
        size: { total: size, downloaded: size * progress, uploaded: 0 },
        speed: { down: 0, up: 0 },
        time: { remaining: 0, elapsed: 0 },
        peers: { seeders: 0, leechers: 0, wires: 0 },
        pieces: { total: torrent.pieces.length, size: torrent.pieceLength }
      })
    } catch (error) {
      console.error(error)
    }
  }
  return torrents
}

export async function importQBittorrent (store: Store, path: string, hashes: string[], move: boolean) {
  const available = new Set(await list())

  const pending = []
  let required = 0
  for (const hash of new Set(hashes)) {
    if (!available.has(hash)) throw new Error(`${hash} is not in the qbittorrent library`)
    if (await store.get(hash)) throw new Error(`${hash} is already imported`)

    const loaded = await load(hash)
    pending.push(loaded)
    required += loaded.torrent.length
  }

  if (!move && await checkAvailableSpace(path) < required) throw new Error(`not enough space to import ${required} bytes`)

  for (const { torrent, resume, data } of pending) {
    const source = arr2text(resume.save_path)
    const files: Array<{ from: string, to: string }> = []
    for (let index = 0, len = torrent.files.length; index < len; ++index) {
      const file = torrent.files[index]
      const renamed = resume.mapped_files?.[index]
      const original = join(source, renamed?.length ? arr2text(renamed) : file.path)
      const to = join(path, file.path)

      for (const from of [original, original + '.!qB', to]) {
        try {
          await access(from)
          files.push({ from, to })
          break
        } catch {}
      }
    }
    if (!files.length) throw new Error(`${torrent.infoHash} has no files to import`)

    for (const { from, to } of files) {
      if (relative(from, to) === '') continue
      await mkdir(dirname(to), { recursive: true })
      if (move) {
        try {
          await rename(from, to)
        } catch {
          await copyFile(from, to)
          await unlink(from)
        }
      } else {
        await copyFile(from, to)
      }
    }

    await store.set(torrent.infoHash, data)
  }
}
