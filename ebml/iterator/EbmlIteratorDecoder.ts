import EbmlTagFactory from './models/EbmlTagFactory.js'
import EbmlTagPosition from './models/enums/EbmlTagPosition.js'
import Tools from './tools.js'

import type EbmlTagId from './models/enums/EbmlTagId.js'
import type EbmlDataTag from './models/tags/EbmlDataTag.js'
import type EbmlMasterTag from './models/tags/EbmlMasterTag.js'

interface TagHeader {
  absoluteStart: number
  tagHeaderLength: number
}

export default class EbmlIteratorDecoder {
  _stream: AsyncIterable<Buffer | Uint8Array> | undefined
  _currentBufferOffset: number
  _tagStack: Array<EbmlMasterTag & TagHeader>
  _buffer: Buffer
  _bufferTagIds: EbmlTagId[]

  constructor (options: { stream?: AsyncIterable<Buffer | Uint8Array>, bufferTagIds?: EbmlTagId[] } = {}) {
    this._stream = options.stream
    this._currentBufferOffset = 0
    this._tagStack = []
    this._buffer = Buffer.alloc(0)
    this._bufferTagIds = options.bufferTagIds ?? []
  }

  get buffer () {
    return this._buffer
  }

  async * [Symbol.asyncIterator] (stream: AsyncIterable<Buffer | Uint8Array> = this._stream!) {
    for await (const chunk of stream) {
      yield * this.parseTags(chunk)
    }
  }

  * parseTags (chunk: Buffer | Uint8Array): Generator<EbmlDataTag | EbmlMasterTag, void, unknown> {
    this._buffer = Buffer.concat([this._buffer, Buffer.from(chunk)])
    while (true) {
      const currentTag = this.readTagHeader(this._buffer)
      if (!currentTag) {
        return
      }
      if ('Children' in currentTag && !this._bufferTagIds.some(i => i === currentTag.id)) {
        this._tagStack.push(currentTag)
        yield this.createTag(currentTag, EbmlTagPosition.Start)
        this.advanceBuffer(currentTag.tagHeaderLength)
      } else {
        if (this._buffer.length < currentTag.tagHeaderLength + currentTag.size) {
          return
        }
        const data = this._buffer.slice(currentTag.tagHeaderLength, currentTag.tagHeaderLength + currentTag.size)
        yield this.createTag(currentTag, EbmlTagPosition.Content, data)
        this.advanceBuffer(currentTag.tagHeaderLength + currentTag.size)
        while (this._tagStack.length > 0) {
          const nextTag = this._tagStack[this._tagStack.length - 1]!
          if (this._currentBufferOffset < (nextTag.absoluteStart + nextTag.tagHeaderLength + nextTag.size)) {
            break
          }
          yield this.createTag(nextTag, EbmlTagPosition.End)
          this._tagStack.pop()
        }
      }
    }
  }

  advanceBuffer (length: number) {
    this._currentBufferOffset += length
    this._buffer = this._buffer.slice(length)
  }

  readTagHeader (buffer: Buffer, offset = 0): (EbmlDataTag | EbmlMasterTag) & TagHeader | null {
    if (buffer.length === 0) return null

    const tag = Tools.readVint(buffer, offset)
    if (tag == null) return null

    const size = Tools.readVint(buffer, offset + tag.length)
    if (size == null) return null

    const tagIdHex = Tools.readHexString(buffer, offset, offset + tag.length)
    const tagId = Number.parseInt(tagIdHex, 16)
    const tagObject = EbmlTagFactory.create(tagId)
    tagObject.size = size.value
    tagObject.sizeLength = size.length
    return Object.assign(tagObject, {
      absoluteStart: this._currentBufferOffset + offset,
      tagHeaderLength: tag.length + size.length
    })
  }

  createTag (tag: (EbmlDataTag | EbmlMasterTag) & TagHeader, position: EbmlTagPosition, data?: Buffer): EbmlDataTag | EbmlMasterTag {
    const emittedTag = EbmlTagFactory.create(tag.id)
    emittedTag.absoluteStart = tag.absoluteStart
    emittedTag.tagHeaderLength = tag.tagHeaderLength
    emittedTag.size = tag.size
    emittedTag.sizeLength = tag.sizeLength
    emittedTag.position = position
    if (position === EbmlTagPosition.Content) {
      emittedTag.parseContent(data!)
    }
    return emittedTag
  }
}
