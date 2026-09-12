import querystring from 'querystring'

// @ts-expect-error no export
import HTTPTracker from 'http-tracker'
import { hex2bin, arr2hex, text2arr } from 'uint8-util'

import type Torrent from 'webtorrent/lib/torrent.js'

export interface ScrapeResponse { hash: string, complete: string, downloaded: string, incomplete: string }

export const ANNOUNCE = [
  // WSS trackers, for now WebRTC is disabled
  // atob('d3NzOi8vdHJhY2tlci5vcGVud2VidG9ycmVudC5jb20='),
  // atob('d3NzOi8vdHJhY2tlci53ZWJ0b3JyZW50LmRldg=='),
  // atob('d3NzOi8vdHJhY2tlci5maWxlcy5mbTo3MDczL2Fubm91bmNl'),
  // atob('d3NzOi8vdHJhY2tlci5idG9ycmVudC54eXov'),
  atob('dWRwOi8vb3Blbi5zdGVhbHRoLnNpOjgwL2Fubm91bmNl'),
  atob('aHR0cDovL255YWEudHJhY2tlci53Zjo3Nzc3L2Fubm91bmNl'),
  atob('dWRwOi8vdHJhY2tlci5vcGVudHJhY2tyLm9yZzoxMzM3L2Fubm91bmNl'),
  atob('dWRwOi8vZXhvZHVzLmRlc3luYy5jb206Njk2OS9hbm5vdW5jZQ=='),
  atob('dWRwOi8vdHJhY2tlci5jb3BwZXJzdXJmZXIudGs6Njk2OS9hbm5vdW5jZQ=='),
  atob('dWRwOi8vOS5yYXJiZy50bzoyNzEwL2Fubm91bmNl'),
  atob('dWRwOi8vdHJhY2tlci50b3JyZW50LmV1Lm9yZzo0NTEvYW5ub3VuY2U='),
  atob('aHR0cDovL29wZW4uYWNnbnh0cmFja2VyLmNvbTo4MC9hbm5vdW5jZQ=='),
  atob('aHR0cDovL2FuaWRleC5tb2U6Njk2OS9hbm5vdW5jZQ=='),
  atob('aHR0cDovL3RyYWNrZXIuYW5pcmVuYS5jb206ODAvYW5ub3VuY2U='),
  atob('aHR0cHM6Ly90cmFja2VyLm5la29idC50by9hcGkvdHJhY2tlci9wdWJsaWMvYW5ub3VuY2U=')
]

const sleep = (t: number) => new Promise(resolve => setTimeout(resolve, t).unref())

const querystringStringify = (obj: Record<string, string>) => {
  let ret = querystring.stringify(obj, undefined, undefined, { encodeURIComponent: escape })
  ret = ret.replace(/[@*/+]/g, char => // `escape` doesn't encode the characters @*/+ so we do it manually
  `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
  return ret
}

export const tracker = new HTTPTracker({}, atob('aHR0cDovL255YWEudHJhY2tlci53Zjo3Nzc3L2Fubm91bmNl'))

export async function scrape (infoHashes: string[]): Promise<ScrapeResponse[]> {
  // this seems to give the best speed, and lowest failure rate
  const MAX_ANNOUNCE_LENGTH = 1300 // it's likely 2048, but lets undercut it
  const RATE_LIMIT = 200 // ms

  const ANNOUNCE_LENGTH = tracker.scrapeUrl.length

  let batch: string[] = []
  let currentLength = ANNOUNCE_LENGTH // fuzz the size a little so we don't always request the same amt of hashes
  const results: ScrapeResponse[] = []

  const scrape = async () => {
    if (results.length) await sleep(RATE_LIMIT)
    const data = await new Promise((resolve, reject) => {
      tracker._request(tracker.scrapeUrl, { info_hash: batch }, (err: Error | null, data: unknown) => {
        if (err) return reject(err)
        resolve(data)
      })
    })

    const { files } = data as { files: Array<Pick<ScrapeResponse, 'complete' | 'downloaded' | 'incomplete'>> }
    const result = []
    for (const [key, data] of Object.entries(files)) {
      result.push({ hash: key.length !== 40 ? arr2hex(text2arr(key)) : key, ...data })
    }

    results.push(...result)
    batch = []
    currentLength = ANNOUNCE_LENGTH
  }

  for (const infoHash of infoHashes.sort(() => 0.5 - Math.random()).map(infoHash => hex2bin(infoHash))) {
    const qsLength = querystringStringify({ info_hash: infoHash }).length + 1 // qs length + 1 for the & or ? separator
    if (currentLength + qsLength > MAX_ANNOUNCE_LENGTH) {
      await scrape()
    }

    batch.push(infoHash)
    currentLength += qsLength
  }
  if (batch.length) await scrape()

  return results
}

export async function getTrackers (torrent: Torrent) {
  torrent.discovery?.tracker.scrape({
    infoHash: torrent.infoHash,
    announce: torrent.announce,
    peerId: torrent.client.peerId,
    port: torrent.client.torrentPort
  })

  const responses: Array<{ complete: number, downloaded: number, incomplete: number, announce: string, failed?: boolean }> = []
  torrent.discovery?.tracker.on('scrape', (res: { complete: number, downloaded: number, incomplete: number, announce: string }) => {
    responses.push(res)
  })

  await sleep(5_000)

  torrent.discovery?.tracker.removeAllListeners('scrape')

  const mappedResponses = Object.fromEntries(responses.map(({ complete, downloaded, incomplete, announce }) => [announce, { complete, downloaded, incomplete, failed: false }]))

  for (const { announceUrl } of torrent.discovery?.tracker._trackers) {
    mappedResponses[announceUrl] ??= { complete: 0, downloaded: 0, incomplete: 0, failed: true }
  }

  return mappedResponses
}
