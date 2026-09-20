import { networkInterfaces } from 'node:os'

function isLinkLocal4 (address: string) {
  return address.startsWith('169.254.')
}

function head (address: string) {
  return Number.parseInt(address.split(':')[0] ?? '0', 16)
}

function isLinkLocal6 (address: string) {
  return (head(address) & 0xffc0) === 0xfe80
}

function toInt (address: string) {
  return address.split('.').reduce((n, octet) => (n << 8) + Number(octet), 0) >>> 0
}

function netmask (bits: number) {
  return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
}

// rank the addresses from the most to the least likely to be reachable by a LAN device
// a 192.168 address is the most common home network. a 100.64 or 198.18 address is a VPN tunnel
// a 172.16 address is often a virtual switch, so an IPv6 address ranks above it
const RANGES = [
  { base: toInt('192.168.0.0'), mask: netmask(16), rank: 0 },
  { base: toInt('10.0.0.0'), mask: netmask(8), rank: 1 },
  { base: toInt('172.16.0.0'), mask: netmask(12), rank: 4 },
  { base: toInt('100.64.0.0'), mask: netmask(10), rank: 6 },
  { base: toInt('198.18.0.0'), mask: netmask(15), rank: 6 }
] as const

function rank4 (value: number) {
  for (const { base, mask, rank } of RANGES) {
    // the >>> 0 in the compare is required. value & mask yields a signed int32, so 192.168.x would not equal the unsigned base without it
    if (((value & mask) >>> 0) === base) return rank
  }
  return 5 // a public address. the address needs NAT loopback
}

// an IPv6 address is a second choice. the support of IPv6 is not universal
// a unique local address is private. a global unicast address is public
function rank6 (address: string) {
  const value = head(address)
  if ((value & 0xfe00) === 0xfc00) return 2 // fc00::/7 unique local
  if ((value & 0xe000) === 0x2000) return 3 // 2000::/3 global unicast
  return 7
}

// return the address that a LAN device can most likely reach
export function networkAddress () {
  const candidates: Array<{ address: string, rank: number }> = []

  for (const addresses of Object.values(networkInterfaces())) {
    for (const { internal, family, address } of addresses ?? []) {
      if (internal) continue
      if (family === 'IPv4' && !isLinkLocal4(address)) {
        candidates.push({ address, rank: rank4(toInt(address)) })
      } else if (family === 'IPv6' && !isLinkLocal6(address)) {
        candidates.push({ address, rank: rank6(address) })
      }
    }
  }

  candidates.sort((a, b) => a.rank - b.rank)

  return toHost(candidates[0]?.address ?? '127.0.0.1')
}

// wrap an IPv6 address in brackets for a URL
function toHost (address: string) {
  return address.includes(':') ? `[${address}]` : address
}
