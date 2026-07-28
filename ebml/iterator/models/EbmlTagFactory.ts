import EbmlElementType from './enums/EbmlElementType.js'
import EbmlTagId from './enums/EbmlTagId.js'
import Block from './tags/Block.js'
import EbmlDataTag from './tags/EbmlDataTag.js'
import EbmlMasterTag from './tags/EbmlMasterTag.js'
import SimpleBlock from './tags/SimpleBlock.js'

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
export default class EbmlTagFactory {
  static create (id: EbmlTagId, type?: EbmlElementType): EbmlDataTag | EbmlMasterTag {
    if (EbmlTagId[id] !== undefined) {
      let foundType
      switch (id) {
        case EbmlTagId.Block:
          return new Block()
        case EbmlTagId.SimpleBlock:
          return new SimpleBlock()
        case EbmlTagId.ChapterDisplay:
        case EbmlTagId.ContentCompression:
        case EbmlTagId.ContentEncryption:
        case EbmlTagId.SilentTracks:
        case EbmlTagId.ContentEncoding:
        case EbmlTagId.TrackTranslate:
        case EbmlTagId.ChapProcessCommand:
        case EbmlTagId.ChapterTranslate:
        case EbmlTagId.ChapProcess:
        case EbmlTagId.Tag:
        case EbmlTagId.Segment:
        case EbmlTagId.SimpleTag:
        case EbmlTagId.Targets:
        case EbmlTagId.Tags:
        case EbmlTagId.ChapterTrack:
        case EbmlTagId.ChapterAtom:
        case EbmlTagId.EditionEntry:
        case EbmlTagId.Chapters:
        case EbmlTagId.AttachedFile:
        case EbmlTagId.Attachments:
        case EbmlTagId.CueReference:
        case EbmlTagId.CueTrackPositions:
        case EbmlTagId.CuePoint:
        case EbmlTagId.Cues:
        case EbmlTagId.ContentEncAESSettings:
        case EbmlTagId.ContentEncodings:
        case EbmlTagId.TrackJoinBlocks:
        case EbmlTagId.TrackPlane:
        case EbmlTagId.TrackCombinePlanes:
        case EbmlTagId.TrackOperation:
        case EbmlTagId.Audio:
        case EbmlTagId.Video:
        case EbmlTagId.TrackEntry:
        case EbmlTagId.Tracks:
        case EbmlTagId.ReferenceFrame:
        case EbmlTagId.TimeSlice:
        case EbmlTagId.Slices:
        case EbmlTagId.BlockMore:
        case EbmlTagId.BlockAdditions:
        case EbmlTagId.BlockGroup:
        case EbmlTagId.Cluster:
        case EbmlTagId.Info:
        case EbmlTagId.Seek:
        case EbmlTagId.SeekHead:
        case EbmlTagId.SignatureElementList:
        case EbmlTagId.SignatureElements:
        case EbmlTagId.SignatureSlot:
        case EbmlTagId.EBML:
          foundType = EbmlElementType.Master
          break
        case EbmlTagId.TrackType:
        case EbmlTagId.FlagDefault:
        case EbmlTagId.ChapterTrackNumber:
        case EbmlTagId.ChapterTimeStart:
        case EbmlTagId.ChapterTimeEnd:
        case EbmlTagId.CueRefTime:
        case EbmlTagId.CueRefCluster:
        case EbmlTagId.ChapterFlagHidden:
        case EbmlTagId.ContentCompAlgo:
        case EbmlTagId.DocTypeReadVersion:
        case EbmlTagId.EBMLVersion:
        case EbmlTagId.DocTypeVersion:
        case EbmlTagId.TagDefault:
        case EbmlTagId.ChapterFlagEnabled:
        case EbmlTagId.FileUsedStartTime:
        case EbmlTagId.FileUsedEndTime:
        case EbmlTagId.ContentEncodingOrder:
        case EbmlTagId.ContentEncodingScope:
        case EbmlTagId.ContentEncodingType:
        case EbmlTagId.CueBlockNumber:
        case EbmlTagId.BitDepth:
        case EbmlTagId.ChapProcessTime:
        case EbmlTagId.ChapProcessCodecID:
        case EbmlTagId.AttachmentLink:
        case EbmlTagId.TagAttachmentUID:
        case EbmlTagId.TagChapterUID:
        case EbmlTagId.TagEditionUID:
        case EbmlTagId.TagTrackUID:
        case EbmlTagId.TargetTypeValue:
        case EbmlTagId.ChapterPhysicalEquiv:
        case EbmlTagId.ChapterSegmentEditionUID:
        case EbmlTagId.ChapterUID:
        case EbmlTagId.EditionFlagOrdered:
        case EbmlTagId.EditionFlagDefault:
        case EbmlTagId.EditionFlagHidden:
        case EbmlTagId.EditionUID:
        case EbmlTagId.FileUID:
        case EbmlTagId.CueRefCodecState:
        case EbmlTagId.CueRefNumber:
        case EbmlTagId.CueCodecState:
        case EbmlTagId.CueDuration:
        case EbmlTagId.CueRelativePosition:
        case EbmlTagId.CueClusterPosition:
        case EbmlTagId.CueTrack:
        case EbmlTagId.CueTime:
        case EbmlTagId.AESSettingsCipherMode:
        case EbmlTagId.ContentSigHashAlgo:
        case EbmlTagId.ContentSigAlgo:
        case EbmlTagId.ContentEncAlgo:
        case EbmlTagId.TrickMasterTrackUID:
        case EbmlTagId.TrickTrackFlag:
        case EbmlTagId.TrickTrackUID:
        case EbmlTagId.TrackJoinUID:
        case EbmlTagId.TrackPlaneType:
        case EbmlTagId.TrackPlaneUID:
        case EbmlTagId.Channels:
        case EbmlTagId.AspectRatioType:
        case EbmlTagId.DisplayUnit:
        case EbmlTagId.DisplayHeight:
        case EbmlTagId.DisplayWidth:
        case EbmlTagId.PixelCropRight:
        case EbmlTagId.PixelCropLeft:
        case EbmlTagId.PixelCropTop:
        case EbmlTagId.PixelCropBottom:
        case EbmlTagId.PixelHeight:
        case EbmlTagId.PixelWidth:
        case EbmlTagId.OldStereoMode:
        case EbmlTagId.AlphaMode:
        case EbmlTagId.StereoMode:
        case EbmlTagId.FlagInterlaced:
        case EbmlTagId.TrackTranslateCodec:
        case EbmlTagId.TrackTranslateEditionUID:
        case EbmlTagId.SeekPreRoll:
        case EbmlTagId.CodecDelay:
        case EbmlTagId.TrackOverlay:
        case EbmlTagId.CodecDecodeAll:
        case EbmlTagId.MaxBlockAdditionID:
        case EbmlTagId.DefaultDecodedFieldDuration:
        case EbmlTagId.DefaultDuration:
        case EbmlTagId.MaxCache:
        case EbmlTagId.MinCache:
        case EbmlTagId.FlagLacing:
        case EbmlTagId.FlagForced:
        case EbmlTagId.FlagEnabled:
        case EbmlTagId.TrackUID:
        case EbmlTagId.TrackNumber:
        case EbmlTagId.ReferenceTimeCode:
        case EbmlTagId.ReferenceOffset:
        case EbmlTagId.SliceDuration:
        case EbmlTagId.Delay:
        case EbmlTagId.BlockAdditionID:
        case EbmlTagId.FrameNumber:
        case EbmlTagId.LaceNumber:
        case EbmlTagId.ReferencePriority:
        case EbmlTagId.BlockDuration:
        case EbmlTagId.BlockAddID:
        case EbmlTagId.PrevSize:
        case EbmlTagId.Position:
        case EbmlTagId.SilentTrackNumber:
        case EbmlTagId.Timecode:
        case EbmlTagId.TimecodeScaleDenominator:
        case EbmlTagId.TimecodeScale:
        case EbmlTagId.ChapterTranslateCodec:
        case EbmlTagId.ChapterTranslateEditionUID:
        case EbmlTagId.SeekPosition:
        case EbmlTagId.SignatureHash:
        case EbmlTagId.SignatureAlgo:
        case EbmlTagId.EBMLMaxSizeLength:
        case EbmlTagId.EBMLMaxIDLength:
        case EbmlTagId.EBMLReadVersion:
          foundType = EbmlElementType.UnsignedInt
          break
        case EbmlTagId.TrackOffset:
        case EbmlTagId.DiscardPadding:
        case EbmlTagId.ReferenceVirtual:
        case EbmlTagId.ReferenceBlock:
          foundType = EbmlElementType.Integer
          break
        case EbmlTagId.CodecID:
        case EbmlTagId.DocType:
        case EbmlTagId.FileMimeType:
        case EbmlTagId.TagLanguage:
        case EbmlTagId.TargetType:
        case EbmlTagId.ChapCountry:
        case EbmlTagId.ChapLanguage:
        case EbmlTagId.CodecDownloadURL:
        case EbmlTagId.CodecInfoURL:
        case EbmlTagId.Language:
          foundType = EbmlElementType.String
          break
        case EbmlTagId.ChapString:
        case EbmlTagId.TagString:
        case EbmlTagId.ChapterStringUID:
        case EbmlTagId.WritingApp:
        case EbmlTagId.SegmentFilename:
        case EbmlTagId.CodecName:
        case EbmlTagId.TagName:
        case EbmlTagId.FileName:
        case EbmlTagId.FileDescription:
        case EbmlTagId.CodecSettings:
        case EbmlTagId.Name:
        case EbmlTagId.MuxingApp:
        case EbmlTagId.Title:
        case EbmlTagId.NextFilename:
        case EbmlTagId.PrevFilename:
          foundType = EbmlElementType.UTF8
          break
        case EbmlTagId.ContentCompSettings:
        case EbmlTagId.SegmentFamily:
        case EbmlTagId.TagBinary:
        case EbmlTagId.FileReferral:
        case EbmlTagId.SignedElement:
        case EbmlTagId.ChapProcessData:
        case EbmlTagId.ChapProcessPrivate:
        case EbmlTagId.ChapterSegmentUID:
        case EbmlTagId.FileData:
        case EbmlTagId.ContentSigKeyID:
        case EbmlTagId.ContentSignature:
        case EbmlTagId.ContentEncKeyID:
        case EbmlTagId.TrickMasterTrackSegmentUID:
        case EbmlTagId.TrickTrackSegmentUID:
        case EbmlTagId.ChannelPositions:
        case EbmlTagId.ColourSpace:
        case EbmlTagId.TrackTranslateTrackID:
        case EbmlTagId.CodecPrivate:
        case EbmlTagId.EncryptedBlock:
        case EbmlTagId.CodecState:
        case EbmlTagId.BlockAdditional:
        case EbmlTagId.BlockVirtual:
        case EbmlTagId.ChapterTranslateID:
        case EbmlTagId.NextUID:
        case EbmlTagId.PrevUID:
        case EbmlTagId.SegmentUID:
        case EbmlTagId.SeekID:
        case EbmlTagId.Signature:
        case EbmlTagId.SignaturePublicKey:
        case EbmlTagId.CRC32:
        case EbmlTagId.Void:
          foundType = EbmlElementType.Binary
          break
        case EbmlTagId.Duration:
        case EbmlTagId.OutputSamplingFrequency:
        case EbmlTagId.SamplingFrequency:
        case EbmlTagId.FrameRate:
        case EbmlTagId.GammaValue:
        case EbmlTagId.TrackTimecodeScale:
          foundType = EbmlElementType.Float
          break
        case EbmlTagId.DateUTC:
          foundType = EbmlElementType.Date
          break
      }
      if (type === undefined) {
        type = foundType
      } else {
        if (type !== foundType) {
          throw new Error(`Trying to create tag of well-known type "${EbmlTagId[id]}" using content type "${type}" (which is incorrect).  Either pass the correct type or ignore the type parameter to EbmlTag.create()`)
        }
      }
    }
    switch (type) {
      case EbmlElementType.Master:
        return new EbmlMasterTag(id)
      case EbmlElementType.UTF8:
      case EbmlElementType.Binary:
      case EbmlElementType.Date:
      case EbmlElementType.Float:
      case EbmlElementType.Integer:
      case EbmlElementType.String:
      case EbmlElementType.UnsignedInt:
      default:
        return new EbmlDataTag(id, type)
    }
  }
}
