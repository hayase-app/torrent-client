import { randomBytes } from 'node:crypto'

import { concat } from 'uint8-util'

export const DHT_BOOTSTRAP = [
  { host: 'dht.libtorrent.org', port: 25401 },
  { host: 'dht.transmissionbt.com', port: 6881 },
  { host: 'router.bittorrent.com', port: 6881 }
]

export const DHT_TEST_INFOHASH = Buffer.from('dd8255ecd7ca55fb0bbf81323d87062db1f6d1c', 'hex')

export const megaBitsToBytes = 1024 * 1024 / 8

// this could... be a bad idea and needs to be verified
export const peerId = concat([[45, 113, 66, 53, 48, 51, 48, 45], randomBytes(12)])
