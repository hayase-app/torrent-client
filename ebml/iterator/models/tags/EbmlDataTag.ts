import Tools from '../../tools.js'
import EbmlTag from '../EbmlTag.js'
import EbmlElementType from '../enums/EbmlElementType.js'
import EbmlTagPosition from '../enums/EbmlTagPosition.js'

import type EbmlTagId from '../enums/EbmlTagId.js'

interface ElementDataMap {
  [EbmlElementType.Master]: never
  [EbmlElementType.UnsignedInt]: number
  [EbmlElementType.Integer]: number
  [EbmlElementType.String]: string
  [EbmlElementType.UTF8]: string | null
  [EbmlElementType.Binary]: Buffer
  [EbmlElementType.Float]: number
  [EbmlElementType.Date]: number
}

export default class EbmlDataTag<T extends EbmlElementType = EbmlElementType> extends EbmlTag {
  declare data: ElementDataMap[T]

  constructor (id: EbmlTagId, type: T = EbmlElementType.Binary as T) {
    super(id, type, EbmlTagPosition.Content)
  }

  parseContent (data: Buffer) {
    switch (this.type) {
      case EbmlElementType.UnsignedInt:
        this.data = Tools.readUnsigned(data) as ElementDataMap[T]
        break
      case EbmlElementType.Float:
        this.data = Tools.readFloat(data) as ElementDataMap[T]
        break
      case EbmlElementType.Integer:
        this.data = Tools.readSigned(data) as ElementDataMap[T]
        break
      case EbmlElementType.String:
        this.data = String.fromCharCode(...data) as ElementDataMap[T]
        break
      case EbmlElementType.UTF8:
        this.data = Tools.readUtf8(data) as ElementDataMap[T]
        break
      default:
        this.data = data as ElementDataMap[T]
        break
    }
  }

  encodeContent () {
    switch (this.type) {
      case EbmlElementType.UnsignedInt:
        return Tools.writeUnsigned(this.data as number | string)
      case EbmlElementType.Float:
        return Tools.writeFloat(this.data as number)
      case EbmlElementType.Integer:
        return Tools.writeSigned(this.data as number)
      case EbmlElementType.String:
        return Buffer.from(this.data as string, 'ascii')
      case EbmlElementType.UTF8:
        return Buffer.from(this.data as string, 'utf8')
      case EbmlElementType.Binary:
      default:
        return this.data as Buffer
    }
  }
}
