import Tools from '../../tools.js'
import BlockLacing from '../enums/BlockLacing.js'
import EbmlElementType from '../enums/EbmlElementType.js'
import EbmlTagId from '../enums/EbmlTagId.js'

import EbmlDataTag from './EbmlDataTag.js'

export default class Block extends EbmlDataTag {
  track!: number
  value!: number
  invisible!: boolean
  lacing!: BlockLacing
  payload!: Buffer

  constructor (subTypeId: EbmlTagId = EbmlTagId.Block) {
    super(subTypeId, EbmlElementType.Binary)
  }

  writeTrackBuffer () {
    return Tools.writeVint(this.track)
  }

  writeValueBuffer () {
    const value = Buffer.alloc(2)
    value.writeInt16BE(this.value, 0)
    return value
  }

  writeFlagsBuffer () {
    let flags = 0x00
    if (this.invisible) {
      flags |= 0b1000
    }
    switch (this.lacing) {
      case BlockLacing.None:
        break
      case BlockLacing.Xiph:
        flags |= 0b0010
        break
      case BlockLacing.EBML:
        flags |= 0b0110
        break
      case BlockLacing.FixedSize:
        flags |= 0b0100
        break
    }
    return Buffer.of(flags)
  }

  encodeContent () {
    return Buffer.concat([
      this.writeTrackBuffer(),
      this.writeValueBuffer(),
      this.writeFlagsBuffer(),
      this.payload
    ])
  }

  parseContent (data: Buffer) {
    const track = Tools.readVint(data)
    this.track = track!.value
    this.value = Tools.readSigned(data.slice(track!.length, track!.length + 2))
    const flags = data[track!.length + 2]!
    this.invisible = Boolean(flags & 0b1000)
    switch (flags & 0b0110) {
      case 0b0000:
        this.lacing = BlockLacing.None
        break
      case 0b0010:
        this.lacing = BlockLacing.Xiph
        break
      case 0b0110:
        this.lacing = BlockLacing.EBML
        break
      case 0b0100:
        this.lacing = BlockLacing.FixedSize
        break
    }
    this.payload = data.slice(track!.length + 3)
  }
}
