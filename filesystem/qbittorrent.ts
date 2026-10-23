import { access, constants, copyFile, mkdir, readdir, readFile, rename, unlink } from 'node:fs/promises'
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
import type { LibraryEntry } from 'native'

export type ImportTorrent = Pick<LibraryEntry, 'hash' | 'mediaID' | 'episode'>

interface ResumeData {
  pieces: Uint8Array
  save_path: Uint8Array
  added_time: number
  mapped_files?: Uint8Array[]
  trackers?: Uint8Array[][]
  'url-list'?: Uint8Array[]
}

function dataFolder () {
  if (platform === 'win32') return env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local')
  if (platform === 'darwin') return join(homedir(), 'Library', 'Application Support')
  return env.XDG_DATA_HOME ?? join(homedir(), '.local', 'share')
}

const backupFolder = () => join(dataFolder(), 'qBittorrent', 'BT_backup')

async function list (folder: string) {
  const names = await readdir(folder).catch(() => [])
  return names.filter(name => extname(name) === '.fastresume').map(name => basename(name, '.fastresume'))
}

const HAVE_PIECE = 1

function toBitfield (pieces: Uint8Array) {
  const bitfield = new BitField(pieces.length)
  pieces.forEach((piece, index) => bitfield.set(index, !!(piece & HAVE_PIECE)))
  return bitfield.buffer
}

async function load (folder: string, hash: string, mediaID = 0, episode = 0) {
  const [state, metadata] = await Promise.all([readFile(join(folder, hash + '.fastresume')), readFile(join(folder, hash + '.torrent'))])
  // @ts-expect-error bad typedefs
  const resume = bencode.decode(state) as ResumeData
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/await-thenable
  const torrent: any = await parseTorrent(metadata)
  if (torrent.infoHash !== hash) throw new Error(`${hash} has no v1 info hash`)

  const data = structTorrent({
    info: torrent.info,
    announce: resume.trackers?.flat().map(url => arr2text(url)),
    urlList: resume['url-list']?.map(url => arr2text(url)),
    private: torrent.private,
    bitfield: toBitfield(resume.pieces),
    date: resume.added_time * 1000,
    mediaID,
    episode
  })

  return { resume, torrent, data }
}

async function locate (...candidates: string[]) {
  for (const candidate of candidates) {
    if (await access(candidate).then(() => true, () => false)) return candidate
  }
}

async function place (from: string, to: string, move: boolean) {
  if (relative(from, to) === '') return
  await mkdir(dirname(to), { recursive: true })
  if (move) {
    try { return await rename(from, to) } catch {}
  }
  await copyFile(from, to + '.part', constants.COPYFILE_FICLONE)
  await rename(to + '.part', to)
  if (move) await unlink(from)
}

async function importTorrent (store: Store, path: string, folder: string, { hash, mediaID, episode }: ImportTorrent, move: boolean) {
  const { resume, torrent, data } = await load(folder, hash, mediaID, episode)
  const source = arr2text(resume.save_path)

  const files: Array<{ from: string, to: string }> = []
  for (const [index, file] of torrent.files.entries()) {
    const renamed = resume.mapped_files?.[index]
    const original = join(source, renamed?.length ? arr2text(renamed) : file.path)
    const to = join(path, file.path)
    const from = await locate(original, original + '.!qB', to)
    if (from) files.push({ from, to })
  }
  if (!files.length) throw new Error(`${hash} has no files to import`)
  if (!move && await checkAvailableSpace(path) < torrent.length) throw new Error(`not enough space to import ${hash}`)

  for (const { from, to } of files) await place(from, to, move)

  await store.set(hash, data)
}

export async function qbittorrentLibrary () {
  const folder = backupFolder()
  const entries: LibraryEntry[] = []
  for (const hash of await list(folder)) {
    try {
      const { torrent, data } = await load(folder, hash)
      entries.push(getLibraryEntry(torrent, data))
    } catch (error) {
      console.error(error)
    }
  }
  return entries
}

export async function importQBittorrent (store: Store, path: string, torrents: ImportTorrent[], move: boolean) {
  const folder = backupFolder()
  const available = new Set(await list(folder))

  const imported: string[] = []
  for (const torrent of torrents) {
    if (!available.has(torrent.hash) || await store.get(torrent.hash)) continue
    try {
      await importTorrent(store, path, folder, torrent, move)
      imported.push(torrent.hash)
    } catch (error) {
      console.error(error)
    }
  }
  return imported
}
