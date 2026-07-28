import Tools from '../../tools.js'
import EbmlTag from '../EbmlTag.js'
import EbmlTagFactory from '../EbmlTagFactory.js'
import EbmlElementType from '../enums/EbmlElementType.js'
import EbmlTagPosition from '../enums/EbmlTagPosition.js'

import type EbmlDataTag from './EbmlDataTag.js'
import type EbmlTagId from '../enums/EbmlTagId.js'

export default class EbmlMasterTag extends EbmlTag {
  _children: Array<EbmlMasterTag | EbmlDataTag> = []

  constructor (id: EbmlTagId, position: EbmlTagPosition = EbmlTagPosition.Content) {
    super(id, EbmlElementType.Master, position)
  }

  get Children () {
    return this._children
  }

  set Children (value) {
    this._children = value
  }

  encodeContent () {
    return Buffer.concat(this._children.map(child => child.encode()))
  }

  parseContent (content: Buffer) {
    while (content.length > 0) {
      const tag = Tools.readVint(content)!
      const size = Tools.readVint(content, tag.length)!
      const tagIdHex = Tools.readHexString(content, 0, tag.length)
      const tagId = Number.parseInt(tagIdHex, 16)
      const tagObject = EbmlTagFactory.create(tagId)
      tagObject.sizeLength = size.length
      tagObject.size = size.value
      const totalTagLength = tag.length + size.length + size.value
      tagObject.parseContent(content.slice(tag.length + size.length, totalTagLength))
      this._children.push(tagObject)
      content = content.slice(totalTagLength)
    }
  }
}
