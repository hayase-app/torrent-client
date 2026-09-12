import { once } from 'node:events'

import NatAPI from '@silentbot1/nat-api'
import DHT from 'bittorrent-dht'

import { DHT_BOOTSTRAP, DHT_TEST_INFOHASH } from '../common/constants.ts'

export async function checkIncomingConnections (testPort: number): Promise<boolean> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), 30_000).unref()
  const dht = new DHT({ bootstrap: DHT_BOOTSTRAP })
  dht.on('error', () => {})
  dht.listen(testPort)
  await once(dht, 'listening')
  await once(dht, 'ready')

  const actualPort = dht.address().port
  const nat = new NatAPI({ enableUPNP: true, enablePMP: true, upnpPermanentFallback: true })
  try {
    if (!await nat.map({ publicPort: actualPort, privatePort: actualPort, protocol: null })) return false
  } catch {
    return false
  } finally {
    await nat.destroy()
  }

  dht.announce(DHT_TEST_INFOHASH, actualPort)

  try {
    await Promise.race([
      once(dht, 'announce_peer', ctrl),
      once(dht, 'get_peers', ctrl)
    ])
    return true
  } catch {
    return false
  } finally {
    clearTimeout(timer)
    await new Promise<void>(resolve => dht.destroy(resolve))
  }
}
