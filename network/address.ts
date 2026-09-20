import { networkInterfaces } from 'node:os'

function isLinkLocal (address: string) {
  return address.startsWith('169.254.')
}

function toInt (address: string) {
  return address.split('.').reduce((n, octet) => (n << 8) + Number(octet), 0) >>> 0
}

function netmask (bits: number) {
  return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
}

// prefer the private range of a home LAN
// rank a virtual switch and a VPN tunnel below a plain address
const RANGES = [
  { base: toInt('192.168.0.0'), mask: netmask(16), priority: 0 },
  { base: toInt('10.0.0.0'), mask: netmask(8), priority: 1 },
  { base: toInt('172.16.0.0'), mask: netmask(12), priority: 2 },
  { base: toInt('100.64.0.0'), mask: netmask(10), priority: 4 },
  { base: toInt('198.18.0.0'), mask: netmask(15), priority: 4 }
] as const

function rank (value: number) {
  for (const { base, mask, priority } of RANGES) {
    // the >>> 0 in the compare is required. value & mask yields a signed int32, so 192.168.x would not equal the unsigned base without it
    if (((value & mask) >>> 0) === base) return priority
  }
  return 3
}

export function networkAddress () {
  const candidates: Array<{ address: string, rank: number }> = []

  for (const addresses of Object.values(networkInterfaces())) {
    for (const { internal, family, address } of addresses ?? []) {
      if (internal || family !== 'IPv4' || isLinkLocal(address)) continue
      candidates.push({ address, rank: rank(toInt(address)) })
    }
  }

  candidates.sort((a, b) => a.rank - b.rank)

  return candidates[0]?.address ?? '127.0.0.1'
}
