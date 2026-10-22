import { on, once } from 'node:events'
import { createSecureServer, type Http2SecureServer, type Http2ServerRequest, type Http2ServerResponse } from 'node:http2'
import { connect } from 'node:net'
import { hostname, userInfo } from 'node:os'
import { buffer } from 'node:stream/consumers'
import { setInterval } from 'node:timers/promises'

import NatAPI from '@silentbot1/nat-api'
import { createRootCA, generateCertificate, type Certificate } from '@stacksjs/tlsx'
import { expose } from 'abslink'
import _debug from 'debug'
import multicastDns from 'multicast-dns'
import pump from 'pump'

import attachments from '../ebml/attachments.ts'
import { client } from '../index.ts'
import { isPrivateAddress } from '../network/address.ts'

import { Channel } from './channel.ts'
import { abort, cors, CHANNEL_ID_LENGTH, decrypt, HOST_KEY, HOSTNAME, localAddress, PORT, PROBE_TIMEOUT, recordType, send } from './util.ts'

import type TorrentClient from '../index.ts'
import type { Answer, Question } from 'dns-packet'
import type { Readable } from 'streamx'

const debug = _debug('host')

async function reachable (host: string) {
  const socket = connect({ host, port: PORT })
  try {
    await once(socket, 'connect', { signal: AbortSignal.timeout(PROBE_TIMEOUT) })
    return true
  } catch {
    return false
  } finally {
    socket.destroy()
  }
}

const APP_RETURN = 'https://hayase.app/#/local/'
const ACCEPT_PAGE = /* html */`<!doctype html><meta charset="utf-8"><title>Hayase</title><script>window.close();location.replace(${JSON.stringify(APP_RETURN)})</script>`

interface WebTorrentResponse {
  status: number
  headers: Record<string, string | number>
  body: Readable & { _readableState?: unknown, _writableState?: unknown } | string
}

export default class HayaseHost {
  _name = `${userInfo().username} (${hostname()})`
  _client: TorrentClient
  _remote: boolean
  _local = false
  _external?: string
  _mdns = multicastDns()
  _channels = new Map<string, Channel>()
  _server: Http2SecureServer | undefined
  _ca: Certificate | undefined
  _nat: NatAPI | undefined
  _ctrl = new AbortController()
  _ready

  constructor (client: TorrentClient, remote = false) {
    this._client = client
    this._remote = remote
    this._ready = this._start()
  }

  async query () {
    await this._ready
    return { local: this._local, external: this._external, name: this._name }
  }

  channel (id: string) {
    const existing = this._channels.get(id)
    if (existing) return existing
    const channel = new Channel(id)
    expose(this._client, channel)
    this._channels.set(id, channel)
    return channel
  }

  async destroy () {
    if (this._destroyed) return
    this._ctrl.abort()
    for (const { _clients } of this._channels.values()) {
      for (const client of _clients) client.end()
    }
    this._channels.clear()
    // a ttl of 0 tells the resolvers to drop the cached record, so the name stops answering
    await new Promise(resolve => this._mdns.respond([{ name: HOSTNAME, type: recordType, ttl: 0, flush: true, data: localAddress }], resolve))
    await Promise.allSettled([
      new Promise<void>(resolve => this._mdns.destroy(resolve)),
      this._server?.[Symbol.asyncDispose](),
      this._nat?.destroy()
    ])
  }

  get _destroyed () {
    return this._ctrl.signal.aborted
  }

  async _start () {
    if (await abort(this._probe())) {
      debug('%s is already announced on this network, access disabled', HOSTNAME)
      return
    }
    if (this._destroyed) return
    try {
      await this._serve()
    } catch (error) {
      debug('access failed: %s', error)
    }
  }

  async _probe () {
    this._mdns.query(HOSTNAME)
    for await (const [{ answers, additionals }] of on(this._mdns, 'response', { signal: AbortSignal.timeout(PROBE_TIMEOUT) }) as AsyncIterable<[{ answers: Answer[], additionals: Answer[] }]>) {
      for (const answer of [...answers, ...additionals]) {
        const { type, name } = answer
        if ((type === 'A' || type === 'AAAA') && name.toLowerCase() === HOSTNAME && 'data' in answer && typeof answer.data === 'string') {
          if (await reachable(answer.data)) return true
        }
      }
    }
  }

  // one http2 listener serves the private network and, through the wan port mapper, the internet
  async _serve () {
    const cert = await this._createCertificate()
    if (this._destroyed) return

    const server = createSecureServer({ ...cert, allowHTTP1: false }, this._handleRequest)
    this._server = server
    server.listen(PORT, '0.0.0.0')
    await abort(once(server, 'listening', { signal: this._ctrl.signal }))
    if (this._destroyed) return
    server.on('error', error => debug('http2 failed: %s', error))

    abort(this._serveMdns())
    this._local = true
    debug('http2 on https://%s:%d', HOSTNAME, PORT)

    // the wan mapping is optional. a failed nat step must not take local access down
    if (this._remote) {
      try {
        await this._mapRemote()
      } catch (error) {
        debug('external access failed: %s', error)
      }
    }
  }

  async setRemote (remote: boolean) {
    await this._ready
    if (this._destroyed || remote === this._remote) return
    this._remote = remote
    try {
      if (remote) await this._mapRemote()
      else await this._unmapRemote()
    } catch (error) {
      debug('external access failed: %s', error)
    }
  }

  async _mapRemote () {
    if (!this._local || this._external) return
    this._nat ??= new NatAPI({ enablePMP: true, enableUPNP: true, upnpPermanentFallback: true })
    const ip = await this._nat.externalIp()
    if (this._destroyed || !ip) return

    this._server?.setSecureContext(await this._createCertificate(ip))
    if (this._destroyed) return
    await this._nat.map({ publicPort: PORT, privatePort: PORT, protocol: 'TCP' })

    this._external = ip
    debug('external http2 on %s', this._external)
  }

  async _unmapRemote () {
    if (!this._external) return
    this._external = undefined
    await this._nat?.unmap({ publicPort: PORT, privatePort: PORT, protocol: 'TCP' })
    debug('external access off')
  }

  async _createCertificate (ip?: string) {
    // reuse one CA, so every certificate change keeps a valid chain
    this._ca ??= await createRootCA({ commonName: `${HOSTNAME} CA` })
    const domains = [HOSTNAME]
    if (recordType === 'A') domains.push(localAddress)
    const altNameIPs = [localAddress]
    if (ip) altNameIPs.push(ip)
    const { certificate, privateKey } = await generateCertificate({
      domain: HOSTNAME,
      domains,
      altNameIPs,
      rootCA: this._ca
    })
    // the server must send the CA certificate, so a client can build the chain
    return { key: privateKey, cert: `${certificate}\n${this._ca.certificate}` }
  }

  // flush marks the record as the unique answer for the name, so resolvers cache it
  _records: [Answer] = [{ name: HOSTNAME, type: recordType, ttl: 120, flush: true, data: localAddress }]

  async _serveMdns () {
    this._mdns.respond(this._records)
    abort(this._announce())
    for await (const [{ questions }, rinfo] of on(this._mdns, 'query', this._ctrl) as AsyncIterable<[{ questions: Question[] }, { port: number }]>) {
      // answer the advertised type (or ANY). leave the other type unanswered so the resolver does not wait out a timeout
      const wanted = questions.some(({ name, type }) => name.toLowerCase() === HOSTNAME && (type === recordType || (type as string) === 'ANY'))
      if (!wanted) continue
      // a query from port 5353 expects a multicast reply, otherwise a unicast reply
      this._mdns.respond(this._records, rinfo.port === 5353 ? undefined : rinfo)
    }
  }

  async _announce () {
    for await (const records of setInterval(20_000, this._records, { ref: false, signal: this._ctrl.signal })) {
      this._mdns.respond(records)
    }
  }

  async _serveEvents (id: string, request: Http2ServerRequest, response: Http2ServerResponse) {
    const channel = this.channel(id)
    response.setHeader('content-type', 'text/event-stream')
    response.setHeader('cache-control', 'no-cache')
    // writeHead flushes the headers, so the page sees an open stream before the first message
    response.writeHead(response.statusCode)
    channel._attach(response)
    try {
      await once(request, 'close')
    } finally {
      if (channel._detach(response)) this._channels.delete(id)
    }
  }

  async _serveMessage (id: string, request: Http2ServerRequest, response: Http2ServerResponse) {
    const channel = this._channels.get(id)
    if (!channel) {
      return send(response, 404)
    }

    try {
      channel.emit('message', await decrypt(await channel._key, await buffer(request)))
      send(response, 204)
    } catch {
      send(response, 400, 'the request body failed to decrypt')
    }
  }

  _serveWebTorrent (id: string, request: Http2ServerRequest, response: Http2ServerResponse) {
    if (!this._channels.has(id)) return send(response, 404)
    if (request.method !== 'GET' && request.method !== 'HEAD') return send(response, 405)

    // the torrent server expects the torrent hash directly after its own route
    const upstream = Object.create(request) as Http2ServerRequest
    Object.defineProperty(upstream, 'url', {
      value: request.url.replace(`/webtorrent/${id}`, '/webtorrent'),
      enumerable: true
    })
    this._client[client]._server!.onRequest(upstream, (result: WebTorrentResponse) => {
      response.writeHead(result.status, result.headers)

      if (typeof result.body !== 'string' && (result.body._readableState ?? result.body._writableState)) {
        pump(result.body, response)
      } else if (typeof result.body === 'string' && result.body) {
        response.end(result.body)
      } else {
        response.end()
      }
    })
  }

  async _serveAttachments (id: string, url: string, request: Http2ServerRequest, response: Http2ServerResponse) {
    if (!this._channels.has(id)) return send(response, 404)
    if (request.method !== 'GET' && request.method !== 'HEAD') return send(response, 405)

    // the attachment server has no route prefix, so remove it before the call
    await attachments.serve(url.slice(`/attachments/${id}`.length) || '/', response)
  }

  _handleRequest = async (request: Http2ServerRequest, response: Http2ServerResponse) => {
    cors(request, response)

    if (request.method === 'OPTIONS') return send(response, 204)

    const [route, id] = new URL(request.url || '/', `https://${HOSTNAME}`).pathname.split('/').slice(1)

    if (id?.length !== CHANNEL_ID_LENGTH || (route !== 'events' && route !== 'message' && route !== 'webtorrent' && route !== 'attachments')) {
      // a browser navigation asks for html. it is the pairing popup, so the page closes itself
      if (request.headers.accept?.includes('text/html')) {
        response.setHeader('content-type', 'text/html')
        return send(response, 200, ACCEPT_PAGE)
      }
      // only a local page receives the secret that derives the channel message keys
      const local = isPrivateAddress(request.socket.remoteAddress ?? '')
      return send(response, 200, { name: this._name, external: this._external, key: local ? HOST_KEY : undefined })
    }

    try {
      if (route === 'webtorrent') {
        this._serveWebTorrent(id, request, response)
      } else if (route === 'attachments') {
        await this._serveAttachments(id, request.url, request, response)
      } else if (route === 'events' && request.method === 'GET') {
        await this._serveEvents(id, request, response)
      } else if (route === 'message' && request.method === 'POST') {
        await this._serveMessage(id, request, response)
      } else {
        send(response, 404)
      }
    } catch (error) {
      // the page closed the connection before the response completed
      debug('channel %s failed: %s', id, error)
    }
  }
}
