import Tools from '../tools.js'

import EbmlTagId from './enums/EbmlTagId.js'

import type EbmlElementType from './enums/EbmlElementType.js'
import type EbmlTagPosition from './enums/EbmlTagPosition.js'

export default class EbmlTag {
  id: EbmlTagId
  type: EbmlElementType | undefined
  position: EbmlTagPosition | undefined
  size!: number
  sizeLength!: number
  absoluteStart!: number
  tagHeaderLength!: number

  constructor (id: EbmlTagId, type?: EbmlElementType, position?: EbmlTagPosition) {
    this.id = id
    this.type = type
    this.position = position
  }

  getTagDeclaration () {
    let tagHex = this.id.toString(16)
    if (tagHex.length % 2 !== 0) {
      tagHex = `0${tagHex}`
    }
    return Buffer.from(tagHex, 'hex')
  }

  encodeContent (): Buffer {
    return Buffer.alloc(0)
  }

  encode () {
    let vintSize: Buffer | null = null
    const content = this.encodeContent()
    if (this.size === -1) {
      vintSize = Buffer.from('01ffffffffffffff', 'hex')
    } else {
      let specialLength: number | undefined
      if ([
        EbmlTagId.Segment,
        EbmlTagId.Cluster
      ].some(i => i === this.id)) {
        specialLength = 8
      }
      vintSize = Tools.writeVint(content.length, specialLength)
    }
    return Buffer.concat([
      this.getTagDeclaration(),
      vintSize,
      content
    ])
  }
}
