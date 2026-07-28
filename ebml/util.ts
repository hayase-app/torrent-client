/* eslint-disable @typescript-eslint/prefer-nullish-coalescing */
import EventEmitter from 'events'

import { EbmlIteratorDecoder, Tools, EbmlTagId, EbmlElementType } from './iterator'

import type { EbmlDataTag, EbmlMasterTag } from './iterator'
import type File from 'webtorrent/lib/file'

function getChild <T extends EbmlTagId> (chunk: EbmlMasterTag | EbmlDataTag, tag: T): EbmlDataTag | undefined {
  if (!('_children' in chunk)) return undefined
  const child = chunk._children.find(child => child.id === tag)
  if (!child) return undefined
  if ('data' in child) return child
  return undefined
}

export default class Util extends EventEmitter {
  file!: File

  destroyed = false
  seekHead?: Promise<Record<string, EbmlDataTag | undefined> | null>
  segment?: Promise<EbmlMasterTag | null>
  duration?: Promise<number | undefined>
  tracks?: Promise<Array<{ number: number, language: string, type: string, _compressed: boolean, default: boolean, forced: boolean, name?: string, header?: string }>>
  segmentStart = 0
  tagCache: Record<string, EbmlMasterTag> = {}

  processTags (tag: EbmlMasterTag | EbmlDataTag) {
    if ('data' in tag && tag.data && (tag.type === EbmlElementType.String || tag.type === EbmlElementType.UTF8 || tag.type == null)) {
      tag.data = String(tag.data)
    }
    if ('Children' in tag) {
      for (const child of tag.Children) {
        this.processTags(child)
      }
    }
    return tag
  }

  async readUntilTag (stream: AsyncIterable<Uint8Array>, tagId: EbmlTagId, bufferTag = true) {
    if (!tagId) throw new Error('tagId is required')

    const decoder = new EbmlIteratorDecoder({ stream, bufferTagIds: bufferTag ? [tagId] : [] })

    for await (const tag of decoder) {
      if (tag.id === tagId) return this.processTags(tag)
    }
    return null
  }

  async readSeekHead (seekHeadStream: AsyncIterable<Uint8Array>, segmentStart: number, recurse = true): Promise<Record<string, EbmlDataTag | undefined> | null> {
    const seekHead = await this.readUntilTag(seekHeadStream, EbmlTagId.SeekHead)
    if (this.destroyed) return null
    if (!seekHead) throw new Error('Couldn\'t find seek head')
    if (!('Children' in seekHead)) throw new Error('Expected SeekHead to be a master tag')

    const transformedHead: Record<string, EbmlDataTag | undefined> = {}

    for (const child of seekHead.Children) {
      if (child.id !== EbmlTagId.Seek) continue
      const tagName = EbmlTagId[Number(Tools.readUnsigned(getChild(child, EbmlTagId.SeekID)!.data as Buffer))]!
      transformedHead[tagName] = getChild(child, EbmlTagId.SeekPosition)
    }

    if (transformedHead.SeekHead && recurse) {
      const seekHeadStream = this.getFileStream(Number(transformedHead.SeekHead.data) + seekHead.absoluteStart)
      const secondSeekHead = await this.readSeekHead(seekHeadStream, segmentStart, false)
      return { ...secondSeekHead, ...transformedHead }
    } else {
      return transformedHead
    }
  }

  getFileStream (start: number | undefined = undefined): AsyncIterable<Uint8Array> {
    return this.file[Symbol.asyncIterator]({ start })
  }

  async getSegment (): Promise<EbmlMasterTag | null> {
    if (this.segment) return await this.segment

    const segment = await this.readUntilTag(this.getFileStream(), EbmlTagId.Segment, false)
    if (!segment || !('Children' in segment)) return null
    this.segmentStart = segment.absoluteStart + segment.tagHeaderLength
    return segment
  }

  async getSeekHead () {
    if (this.seekHead) return await this.seekHead

    await this.segment

    const seekHeadStream = this.getFileStream()
    return await this.readSeekHead(seekHeadStream, 0)
  }

  async readSeekHeadTag (tag: string) {
    const seekHead = await this.seekHead

    if (!seekHead) return null

    const storedTag = tag.toLowerCase()
    if (!this.tagCache[storedTag] && seekHead[tag]) {
      const stream = this.getFileStream()
      const child = await this.readUntilTag(stream, EbmlTagId[tag as keyof typeof EbmlTagId])
      if (!child) return null
      child.absoluteStart = this.segmentStart + (Number(seekHead[tag]?.data) || 0)
      if (!('Children' in child)) return null
      this.tagCache[storedTag] = child

      return this.tagCache[storedTag]
    }
    return this.tagCache[storedTag]
  }
}
