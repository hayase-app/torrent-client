/* eslint-disable @typescript-eslint/prefer-nullish-coalescing */
import { inflateSync } from 'zlib'

import { arr2text, concat } from 'uint8-util'

import { EbmlIteratorDecoder, EbmlTagId } from './iterator'
import Util from './util.ts'

import type { EbmlDataTag, EbmlMasterTag } from './iterator'
import type File from 'webtorrent/lib/file'
import 'fast-readable-async-iterator'

function getChild <T extends EbmlTagId> (chunk?: EbmlMasterTag | EbmlDataTag, tag?: T): EbmlMasterTag | EbmlDataTag | undefined {
  // @ts-expect-error w/e
  return chunk?.Children?.find(child => child.id === tag)
}

function getData <T extends EbmlTagId> (chunk?: EbmlMasterTag | EbmlDataTag, tag?: T) {
  return getChild(chunk, tag)?.data
}

export default class Metadata extends Util {
  timecodeScale = 1
  currentClusterTimecode: number | null = null

  destroyed = false

  subtitleTracks = new Map<string | number, {number: number, language: string, type: string, _compressed: boolean, default: boolean, forced: boolean, name?: string, header?: string}>()

  constructor (file: File) {
    super()
    this.file = file

    this.segment = this.getSegment()
    this.seekHead = this.getSeekHead()
    this.duration = this.getDuration()
    this.tracks = this.getTracks()
  }

  async getAttachments () {
    return (await this.readSeekHeadTag('Attachments'))?.Children?.map(chunk => ({
      filename: getData(chunk, EbmlTagId.FileName)?.toString() ?? '',
      mimetype: getData(chunk, EbmlTagId.FileMimeType)?.toString() ?? '',
      data: getData(chunk, EbmlTagId.FileData) ?? ''
    })) ?? []
  }

  async getTracks () {
    if (this.tracks) return await this.tracks
    const Tracks = await this.readSeekHeadTag('Tracks')

    if (!Tracks?.Children?.length) return []

    for (const entry of Tracks.Children) {
      if (entry.id !== EbmlTagId.TrackEntry) continue
      if (getData(entry, EbmlTagId.TrackType) !== 0x11) continue

      const codecID = String(getData(entry, EbmlTagId.CodecID) || '')
      if (codecID.startsWith('S_TEXT')) {
        const track: {
          number: number
          language: string
          type: string
          default: boolean
          forced: boolean
          name: string | undefined
          _compressed: boolean
          header?: string
        } = {
          number: Number(getData(entry, EbmlTagId.TrackNumber)),
          language: String(getData(entry, EbmlTagId.Language) || 'eng'),
          type: codecID.substring(7).toLowerCase(),
          default: Boolean(getData(entry, EbmlTagId.FlagDefault) ?? 1),
          forced: Boolean(getData(entry, EbmlTagId.FlagForced) || 0),
          name: getData(entry, EbmlTagId.Name) as string | undefined,
          _compressed: 'Children' in entry && entry.Children.some(c =>
            c.id === EbmlTagId.ContentEncodings && 'Children' in c && c.Children.some(cc =>
              cc.id === EbmlTagId.ContentEncoding &&
              getChild(cc, EbmlTagId.ContentCompression)
            )
          )
        }

        const header = getData(entry, EbmlTagId.CodecPrivate)
        if (header instanceof Buffer) track.header = arr2text(header)

        this.subtitleTracks.set(track.number, track)
      }
    }

    return [...this.subtitleTracks.values()]
  }

  async getChapters () {
    const Chapters = await this.readSeekHeadTag('Chapters')

    let timecodeScale = this.timecodeScale
    if (!timecodeScale) {
      const tag = await this.readUntilTag(this.getFileStream(), EbmlTagId.TimecodeScale)
      if (tag && 'data' in tag) this.timecodeScale = timecodeScale = Number(tag.data) / 1000000
    }

    if (!Chapters?.Children?.length) return []

    const editions = Chapters.Children.filter(c => c.id === EbmlTagId.EditionEntry)

    const defaultEdition = editions.find((c): c is EbmlMasterTag =>
      'Children' in c && c.Children.some(cc =>
        cc.id === EbmlTagId.EditionFlagDefault && 'data' in cc && cc.data
      )
    ) || editions[0]!

    const atoms = 'Children' in defaultEdition
      ? defaultEdition.Children.filter(c => c.id === EbmlTagId.ChapterAtom && !getData(c, EbmlTagId.ChapterFlagHidden))
      : []

    const chapters: Array<{ start: number, end: number, text: string, language: string }> = []
    for (let i = atoms.length - 1; i >= 0; --i) {
      const start = Number(getData(atoms[i], EbmlTagId.ChapterTimeStart)) / timecodeScale / 1000000
      const end = Number(getData(atoms[i], EbmlTagId.ChapterTimeEnd)) / timecodeScale / 1000000 || chapters[i + 1]?.start || await this.duration || 0
      const disp = getChild(atoms[i], EbmlTagId.ChapterDisplay)

      chapters[i] = {
        start,
        end,
        text: getData(disp, EbmlTagId.ChapString)?.toString() ?? '',
        language: getData(disp, EbmlTagId.ChapLanguage)?.toString() ?? ''
      }
    }

    return chapters
  }

  async getDuration () {
    if (this.duration) return await this.duration
    const Info = await this.readSeekHeadTag('Info')

    if (!Info?.Children?.length) return undefined
    const Duration = getChild(Info, EbmlTagId.Duration)
    return Duration?.data !== undefined ? Number(Duration.data) : undefined
  }

  async handleBlockGroup (chunk: EbmlMasterTag, timecodeScale: number, currentClusterTimecode: number) {
    await this.tracks

    const block = getChild(chunk, EbmlTagId.Block) as EbmlDataTag & { track: number, value: number, payload: Buffer } | undefined

    if (block && this.subtitleTracks.has(block.track)) {
      const blockDuration = Number(getData(chunk, EbmlTagId.BlockDuration))
      const track = this.subtitleTracks.get(block.track)

      if (!track) return

      const payload = track._compressed
        ? inflateSync(block.payload)
        : block.payload

      const subtitle = {
        text: arr2text(payload),
        time: (block.value + currentClusterTimecode) * timecodeScale,
        duration: blockDuration * timecodeScale
      }

      this.emit('subtitle', subtitle, block.track)
    }
  }

  destroy () {
    this.destroyed = true
  }

  async * parseStream (stream: AsyncIterable<Uint8Array>, stable = false) {
    const decoder = new EbmlIteratorDecoder({
      bufferTagIds: [
        EbmlTagId.TimecodeScale,
        EbmlTagId.BlockGroup,
        EbmlTagId.Timecode
      ]
    })

    let timecodeScale = this.timecodeScale
    let currentClusterTimecode = this.currentClusterTimecode

    const tagMap: Record<number, (tag: EbmlMasterTag | EbmlDataTag) => void> = {
      [EbmlTagId.TimecodeScale]: (tag) => {
        if ('data' in tag) this.timecodeScale = timecodeScale = Number(tag.data) / 1000000
      },
      [EbmlTagId.Timecode]: (tag) => {
        if ('data' in tag) this.currentClusterTimecode = currentClusterTimecode = tag.data == null ? null : Number(tag.data)
      },
      [EbmlTagId.BlockGroup]: (tag) => {
        if ('Children' in tag) this.handleBlockGroup(tag, timecodeScale, currentClusterTimecode ?? 0)
      }
    }

    let buffer: Uint8Array | null = new Uint8Array()

    for await (const chunk of stream) {
      if (!stable) {
        for (let i = 0; i < chunk.length - 12; i++) {
          if (chunk[i] === 0x1f && chunk[i + 1] === 0x43 && chunk[i + 2] === 0xb6 && chunk[i + 3] === 0x75) {
            const len = 8 - Math.floor(Math.log2(chunk[i + 4]!))
            if (EbmlTagId[chunk[i + 4 + len]!]) {
              stable = true
              buffer = null
              for (const tag of decoder.parseTags(chunk.slice(i))) {
                tagMap[tag.id]?.(tag)
              }
              break
            }
          }
        }
        if (!stable) {
          buffer = concat([buffer!, chunk])
        }
      } else {
        for (const tag of decoder.parseTags(chunk)) {
          tagMap[tag.id]?.(tag)
        }
      }
      yield chunk
      if (this.destroyed) return null
    }
  }

  async parseFile () {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of this.parseStream(this.getFileStream(), true)) {
      if (this.destroyed) return null
    }
  }
}
