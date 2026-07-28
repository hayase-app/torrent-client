import Tools from '../../tools.js'
import EbmlTagId from '../enums/EbmlTagId.js'

import Block from './Block.js'

export default class SimpleBlock extends Block {
  keyframe!: boolean
  discardable!: boolean

  constructor () {
    super(EbmlTagId.SimpleBlock)
  }

  encodeContent () {
    const flags = this.writeFlagsBuffer()
    if (this.keyframe) {
      flags[0]! |= 0x80
    }
    if (this.discardable) {
      flags[0]! |= 0x01
    }
    return Buffer.concat([
      this.writeTrackBuffer(),
      this.writeValueBuffer(),
      flags,
      this.payload
    ])
  }

  parseContent (data: Buffer) {
    super.parseContent(data)
    const track = Tools.readVint(data)!
    const flags = data[track.length + 2]!
    this.keyframe = Boolean(flags & 0x80)
    this.discardable = Boolean(flags & 0x01)
  }
}
