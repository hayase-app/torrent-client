import dns from 'node:dns'

import type { LookupAddress } from 'node:dns'
import type { LookupFunction } from 'node:net'

interface DNSAnswer {
  Status: number
  TC: boolean
  RD: boolean
  RA: boolean
  AD: boolean
  CD: boolean
  Question: Array<{ name: string, type: number }>
  Answer?: Array<{ name: string, type: number, TTL: number, data: string }>
}

const DNS_TYPES = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  NS: 2,
  PTR: 12
} as const

// https://source.chromium.org/chromium/chromium/src/+/main:net/dns/public/doh_provider_entry.cc;l=64
export const PROVIDERS = {
  'doh.cleanbrowsing.org/doh/adult-filter': ['185.228.168.10', '185.228.169.11', '[2a0d:2a00:1::1]', '[2a0d:2a00:2::1]'],
  'doh.cleanbrowsing.org/doh/family-filter': ['185.228.168.168', '185.228.169.168', '[2a0d:2a00:1::]', '[2a0d:2a00:2::]'],
  'doh.cleanbrowsing.org/doh/security-filter': ['185.228.168.9', '185.228.169.9', '[2a0d:2a00:1::2]', '[2a0d:2a00:2::2]'],
  'cloudflare-dns.com/dns-query': ['1.1.1.1', '1.0.0.1', '[2606:4700:4700::1111]', '[2606:4700:4700::1001]'],
  'one.one.one.one/dns-query': ['1.1.1.1', '1.0.0.1', '[2606:4700:4700::1111]', '[2606:4700:4700::1001]'],
  'doh.xfinity.com/dns-query': ['75.75.75.75', '75.75.76.76', '[2001:558:feed::1]', '[2001:558:feed::2]'],
  'doh.cox.net/dns-query': ['68.105.28.11', '68.105.28.12', '[2001:578:3f::30]'],
  'odvr.nic.cz/doh': ['185.43.135.1', '193.17.47.1', '[2001:148f:fffe::1]', '[2001:148f:ffff::1]'],
  'doh.dns.sb/dns-query': ['185.222.222.222', '45.11.45.11', '[2a09::]', '[2a11::]'],
  'dns.google/dns-query': ['8.8.8.8', '8.8.4.4', '[2001:4860:4860::8888]', '[2001:4860:4860::8844]'],
  'dns64.dns.google/dns-query': ['[2001:4860:4860::64]', '[2001:4860:4860::6464]'],
  'dns.levonet.sk/dns-query': ['109.236.119.2', '109.236.120.2', '[2a02:6ca3:0:1::2]', '[2a02:6ca3:0:2::2]'],
  'doh.opendns.com/dns-query': ['208.67.222.222', '208.67.220.220', '[2620:119:35::35]', '[2620:119:53::53]'],
  'doh.familyshield.opendns.com/dns-query': ['208.67.222.123', '[208.67.220.123]', '[2620:119:35::123]', '[2620:119:53::123]'],
  'dns11.quad9.net/dns-query': ['9.9.9.11', '149.112.112.11', '[2620:fe::11]', '[2620:fe::fe:11]'],
  'dns10.quad9.net/dns-query': ['9.9.9.10', '149.112.112.10', '[2620:fe::10]', '[2620:fe::fe:10]'],
  'dns.quad9.net/dns-query': ['9.9.9.9', '149.112.112.112', '[2620:fe::fe]', '[2620:fe::9]'],
  'doh.quickline.ch/dns-query': ['212.60.61.246', '212.60.63.246', '[2001:1a88:10:ffff::1]', '[2001:1a88:10:ffff::2]'],
  'doh-01.spectrum.com/dns-query': ['209.18.47.61', '209.18.47.62', '[2001:1998:0f00:0001::1]', '[2001:1998:0f00:0002::1]'],
  'doh-02.spectrum.com/dns-query': ['209.18.47.61', '209.18.47.62', '[2001:1998:0f00:0001::1]', '[2001:1998:0f00:0002::1]']
} as const

export default class DoHResolver {
  dohServers
  pathname
  originalLookup = dns.lookup

  constructor (dohServer = 'https://cloudflare-dns.com/dns-query') {
    if (!(dohServer.slice(8) in PROVIDERS)) dohServer = 'https://cloudflare-dns.com/dns-query'

    this.dohServers = PROVIDERS[dohServer.slice(8) as keyof typeof PROVIDERS]
    this.pathname = new URL(dohServer).pathname
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    dns.lookup = this._lookup as any
  }

  _lookup: LookupFunction = async (hostname, options, callback) => {
    if (hostname === 'localhost' || hostname === '0.0.0.0' || hostname === '::1' || hostname === '127.0.0.1') return this.originalLookup(hostname, options, callback)
    try {
      // Resolves a host name (e.g. `'nodejs.org'`) into the first found A (IPv4) or
      // AAAA (IPv6) record. All `option` properties are optional. If `options` is an
      // integer, then it must be `4` or `6` – if `options` is `0` or not provided, then
      // IPv4 and IPv6 addresses are both returned if found.
      // With the `all` option set to `true`, the arguments for `callback` change to `(err, addresses)`, with `addresses` being an array of objects with the
      // properties `address` and `family`.
      const results: Array<ReturnType<typeof this.resolve>> = []
      if (options.all) {
        results.push(this.resolve(hostname, 'A'))
        results.push(this.resolve(hostname, 'AAAA'))
      } else {
        results.push(this.resolve(hostname, options.family === 6 ? 'AAAA' : 'A'))
      }

      const settledResults = await Promise.allSettled(results)
      const addresses = settledResults
        .filter(result => result.status === 'fulfilled')
        .flatMap(({ value }) => value)

      if (!addresses.length) {
        const errors = settledResults
          .filter(result => result.status === 'rejected')
          .map(result => result.reason.message).join(', ')
        throw new Error('All DNS lookups failed:' + errors)
      }

      if (options.all) {
        callback(null, addresses)
      } else {
        const firstAddress = addresses[0]
        if (firstAddress) {
          callback(null, firstAddress.address, firstAddress.family)
        } else {
          throw new Error('No address found')
        }
      }
    } catch (error) {
      // Fallback to original lookup on error
      this.originalLookup(hostname, options, callback)
    }
  }

  async resolve (name: string, type: keyof typeof DNS_TYPES = 'A') {
    const ip = type === 'AAAA' ? this.dohServers.find(ip => ip.includes(':')) : this.dohServers.find(ip => !ip.includes(':'))

    if (!ip) throw new Error('No IP found for the requested type')

    const response = await fetch(`https://${ip}${this.pathname}?name=${name}&type=${type}`, {
      method: 'GET',
      headers: {
        Accept: 'application/dns-json',
        'User-Agent': 'Node.js DoH Client'
      },
      signal: AbortSignal.timeout(5000)
    })

    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`)

    const data: DNSAnswer = await response.json()

    if (data.Status !== 0) throw new Error(`DNS query failed with status: ${data.Status}`)

    return (data.Answer ?? [])
      .filter(answer => answer.type === DNS_TYPES[type])
      .map<LookupAddress>(answer => ({ address: answer.data, family: answer.type === 28 ? 6 : 4 }))
  }

  destroy () {
    dns.lookup = this.originalLookup
  }
}
