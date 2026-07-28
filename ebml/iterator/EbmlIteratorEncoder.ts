import EbmlTagId from './models/enums/EbmlTagId.js'
import EbmlTagPosition from './models/enums/EbmlTagPosition.js'

import type EbmlDataTag from './models/tags/EbmlDataTag.js'
import type EbmlMasterTag from './models/tags/EbmlMasterTag.js'

export default class EbmlIteratorEncoder {
  _stream: AsyncIterable<EbmlDataTag | EbmlMasterTag> | undefined
  buffer: Buffer
  openTags: EbmlMasterTag[]

  constructor ({ stream }: { stream?: AsyncIterable<EbmlDataTag | EbmlMasterTag> } = {}) {
    this._stream = stream
    this.buffer = Buffer.alloc(0)
    this.openTags = []
  }

  async * [Symbol.asyncIterator] (stream: AsyncIterable<EbmlDataTag | EbmlMasterTag>) {
    for await (const tag of stream) {
      const chunk = this.processTag(tag)
      if (chunk) yield chunk
    }
  }

  processTag (tag: EbmlDataTag | EbmlMasterTag) {
    if (tag) {
      if (!tag.id) throw new Error(`No id found for ${JSON.stringify(tag)}`)
      switch (tag.position) {
        case EbmlTagPosition.Start:
          if ('Children' in tag) this.startTag(tag)
          return
        case EbmlTagPosition.Content:
          return this.writeTag(tag)
        case EbmlTagPosition.End:
          if ('Children' in tag) return this.endTag(tag)
      }
    }
  }

  constructBuffer (buffer: Buffer): Buffer | undefined {
    this.buffer = Buffer.concat([this.buffer, buffer])
    if (this.buffer.length > 0) {
      const chunk = Buffer.from(this.buffer)
      this.buffer = Buffer.alloc(0)
      return chunk
    }
  }

  writeTag (tag: EbmlDataTag | EbmlMasterTag): Buffer | undefined {
    if (this.openTags.length > 0) {
      this.openTags[this.openTags.length - 1]!.Children.push(tag)
    } else {
      return this.constructBuffer(tag.encode())
    }
  }

  startTag (tag: EbmlMasterTag) {
    if (this.openTags.length > 0) {
      this.openTags[this.openTags.length - 1]!.Children.push(tag)
    }
    this.openTags.push(tag)
  }

  endTag (tag: EbmlMasterTag): Buffer | undefined {
    const inMemoryTag = this.openTags.pop()!
    if (tag.id !== inMemoryTag.id) {
      throw new Error(`Logic error - closing tag "${EbmlTagId[tag.id]}" is not expected tag "${EbmlTagId[inMemoryTag.id]}"`)
    }
    if (this.openTags.length < 1) {
      return this.constructBuffer(inMemoryTag.encode())
    }
    return undefined
  }
}
