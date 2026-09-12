import BitField from 'bitfield'
import peerid from 'bittorrent-peerid'

import type { TorrentData } from '../filesystem/store.ts'
import type { LibraryEntry, PeerInfo, TorrentInfo } from 'native'
import type Torrent from 'webtorrent/lib/torrent.js'

function getWireProgress (wire: Torrent['wires'][number], torrent: Torrent): number {
  if (!wire.peerPieces) return 0
  let downloaded = 0
  for (let index = 0, len = torrent.pieces.length; index < len; ++index) {
    if (wire.peerPieces.get(index)) { // verified data
      // @ts-expect-error bad typedefs
      downloaded += (index === len - 1) ? torrent.lastPieceLength : torrent.pieceLength
    }
  }
  // @ts-expect-error bad typedefs
  return torrent.length ? downloaded / torrent.length : 0
}

export function getStats (torrent: Torrent): TorrentInfo {
  // @ts-expect-error bad typedefs
  const seeders = torrent.wires.filter(wire => wire.isSeeder).length
  const leechers = torrent.wires.length - seeders
  const wires = torrent._peersLength
  // @ts-expect-error bad typedefs
  const { infoHash: hash, timeRemaining: remaining, length: total, name, progress, downloadSpeed: down, uploadSpeed: up, downloaded, uploaded, pieces, pieceLength } = torrent

  return {
    hash,
    name,
    peers: {
      seeders, leechers, wires
    },
    progress,
    speed: {
      down,
      up
    },
    size: {
      downloaded,
      uploaded,
      total
    },
    time: {
      remaining,
      elapsed: 0
    },
    pieces: {
      total: pieces.length,
      size: pieceLength
    }
  }
}

export function getPeerInfo (torrent: Torrent): PeerInfo[] {
  const peers: PeerInfo[] = torrent.wires.map(wire => {
    const flags: Array<'incoming' | 'outgoing' | 'utp' | 'encrypted'> = []

    const type = wire.type
    if (type.startsWith('utp')) flags.push('utp')
    flags.push(type.endsWith('Incoming') ? 'incoming' : 'outgoing')
    if (wire._cryptoHandshakeDone) flags.push('encrypted')

    const parsed = peerid(wire.peerId!)

    const progress = getWireProgress(wire, torrent)

    const isWebSeed = wire.type === 'webSeed'
    // @ts-expect-error bad typedefs
    const ip = isWebSeed ? (wire.domain ?? wire.remoteAddress) : wire.remoteAddress.replace(/^::ffff:/, '') + ':' + wire.remotePort
    // @ts-expect-error bad typedefs
    const client = isWebSeed ? (wire.webSeedType ?? 'http') : `${parsed.client} ${parsed.version ?? ''}`

    return {
      ip,
      // @ts-expect-error bad typedefs
      seeder: wire.isSeeder,
      client,
      progress,
      size: {
        downloaded: wire.downloaded,
        uploaded: wire.uploaded
      },
      speed: {
        down: wire.downloadSpeed(),
        up: wire.uploadSpeed()
      },
      time: 0,
      flags
    }
  })

  return peers
}

export function getFileInfo (torrent: Torrent) {
  return torrent.files.map(({ name, length, progress, _iterators }) => ({
    name,
    size: length,
    progress,
    selections: _iterators.size
  }))
}

export function getProtocolStatus (client: Torrent['client'], torrent: Torrent, persist: boolean) {
  return {
    dht: !!client.dhtPort,
    lsd: !!torrent.discovery?.lsd?.server,
    pex: !torrent.private,
    nat: !!client.natTraversal?._pmpClient && !!client.natTraversal?._upnpClient, //! !await client.natTraversal?.externalIp(),
    forwarding: !!torrent._peers.values().find(peer => peer.type === 'utpIncoming' || peer.type === 'tcpIncoming'),
    persisting: !!persist,
    streaming: !!torrent._startAsDeselected
  }
}

export function getLibraryEntry (torrent: Torrent, bencoded: TorrentData): LibraryEntry {
  const bitfield = new BitField(bencoded._bitfield ?? new Uint8Array(0))

  // @ts-expect-error bad typedefs
  const { length: total, name, lastPieceLength, pieceLength } = torrent

  let downloaded = 0
  for (let index = 0, len = torrent.pieces.length; index < len; ++index) {
    if (bitfield.get(index)) { // verified data
      downloaded += (index === len - 1) ? lastPieceLength : pieceLength
    }
  }
  const progress = total ? downloaded / total : 0

  return {
    mediaID: bencoded.mediaID,
    episode: bencoded.episode,
    files: torrent.files.length,
    hash: torrent.infoHash,
    progress,
    date: bencoded.date,
    size: total,
    name
  }
}
