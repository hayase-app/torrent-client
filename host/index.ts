import { EventEmitter, on, once } from 'node:events'
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { hostname, userInfo } from 'node:os'
import { text } from 'node:stream/consumers'
import { setInterval } from 'node:timers/promises'

import NatAPI from '@silentbot1/nat-api'
import _debug from 'debug'
import multicastDns from 'multicast-dns'
import selfsigned, { type SubjectAltNameEntry } from 'selfsigned'

import { isPrivateAddress } from '../network/address.ts'

import { Channel } from './channel.ts'
import { abort, cors, CHANNEL_ID_LENGTH, HOSTNAME, HTTP_PORT, HTTPS_PORT, localAddress, PROBE_TIMEOUT, recordType, send } from './util.ts'

import type { Answer, Question } from 'dns-packet'

// TODO: implement key exchange for local

const debug = _debug('host')

export default new class HayaseHost extends EventEmitter<{ channel: [channel: Channel] }> {
  _name = `${userInfo().username} (${hostname()})`
  _local = false
  _external: { ip: string, port: number, url: string } | undefined
  _mdns = multicastDns()
  _channels = new Map<string, Channel>()
  _servers: Server[] = []
  _nat: NatAPI | undefined
  _ctrl = new AbortController()
  _ready

  constructor () {
    super()
    this._ready = this._start()
  }

  async query () {
    await this._ready
    return { local: this._local, external: this._external, name: this._name }
  }

  // return the channel of an id. the page creates the channel with its first request
  channel (id: string) {
    let channel = this._channels.get(id)
    if (!channel) {
      channel = new Channel(id)
      this._channels.set(id, channel)
      this.emit('channel', channel)
    }
    return channel
  }

  // stop the servers, the responder and the open event streams, so the process can exit
  async destroy () {
    if (this._destroyed) return
    this._ctrl.abort()
    for (const { _clients } of this._channels.values()) {
      for (const client of _clients) client.end()
    }
    this._channels.clear()
    await Promise.allSettled([
      ...this._servers.map(server => {
        server.closeAllConnections()
        return server[Symbol.asyncDispose]()
      }),
      new Promise<void>(resolve => this._mdns.destroy(resolve)),
      this._nat?.destroy()
    ])
  }

  get _destroyed () {
    return this._ctrl.signal.aborted
  }

  async _start () {
    if (await abort(this._probe())) {
      // external access authenticates with the key handed out locally, so it is pointless without local access
      debug('%s is already announced on this network, local and external access disabled', HOSTNAME)
      return
    }
    if (this._destroyed) return
    try {
      await this._serveLocal()
      if (this._destroyed) return
      this._local = true
    } catch (error) {
      debug('local access failed: %s', error)
    }
    // await this._serveExternal()
  }

  // ask the network if another device already answers for our name. our own responder is not listening yet
  async _probe () {
    this._mdns.query(HOSTNAME)
    for await (const [{ answers, additionals }] of on(this._mdns, 'response', { signal: AbortSignal.timeout(PROBE_TIMEOUT) }) as AsyncIterable<[{ answers: Answer[], additionals: Answer[] }]>) {
      for (const { type, name } of [...answers, ...additionals]) {
        if ((type === 'A' || type === 'AAAA') && name.toLowerCase() === HOSTNAME) return true
      }
    }
  }

  async _serveLocal () {
    const server = createHttpServer(this._handleRequest)
    this._servers.push(server)
    server.listen(HTTP_PORT, '0.0.0.0')
    // once rejects on the error event, so a taken port fails the start
    await abort(once(server, 'listening', { signal: this._ctrl.signal }))
    if (this._destroyed) return
    server.on('error', error => debug('http failed: %s', error))
    abort(this._serveMdns())
    debug('local http on http://%s:%d', HOSTNAME, HTTP_PORT)
  }

  async _serveExternal () {
    this._nat = new NatAPI({ enablePMP: true, enableUPNP: true, upnpPermanentFallback: true })
    try {
      const ip = await this._nat.externalIp()
      if (this._destroyed) return
      if (!ip) throw new Error('could not read the external ip')

      const cert = await this._createCertificate(ip)
      if (this._destroyed) return

      const https = createHttpsServer(cert, this._handleRequest)
      this._servers.push(https)
      https.on('error', error => debug('https failed: %s', error))
      https.listen(HTTPS_PORT, '0.0.0.0')

      await this._nat.map({ publicPort: HTTPS_PORT, privatePort: HTTPS_PORT, protocol: 'TCP' })
      if (this._destroyed) return

      this._external = { ip, port: HTTPS_PORT, url: `https://${ip}:${HTTPS_PORT}` }
      debug('external https on %s', this._external.url)
    } catch (error) {
      if (this._destroyed) return
      debug('external access failed: %s', error)
    }
  }

  // the external address is a bare ip, so the certificate carries an ip SAN. the browser accepts it once
  async _createCertificate (ip: string) {
    const altNames: SubjectAltNameEntry[] = [
      { type: 7, ip },
      { type: 2, value: 'localhost' },
      { type: 7, ip: '127.0.0.1' },
      { type: 7, ip: localAddress }
    ]
    if (recordType === 'A') altNames.push({ type: 2, value: localAddress })
    const pems = await selfsigned.generate(
      [{ name: 'commonName', value: ip }],
      {
        notAfterDate: new Date(Date.now() + 3650 * 24 * 60 * 60 * 1000),
        keySize: 2048,
        algorithm: 'sha256',
        extensions: [
          { name: 'basicConstraints', cA: false },
          { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
          { name: 'extKeyUsage', serverAuth: true },
          { name: 'subjectAltName', altNames }
        ]
      }
    )
    return { key: pems.private, cert: pems.cert }
  }

  // flush marks the record as the unique answer for the name, so resolvers cache it
  _records: [Answer] = [{ name: HOSTNAME, type: recordType, ttl: 120, flush: true, data: localAddress }]

  async _serveMdns () {
    // the first announcement primes the resolver caches. later lookups reach us through their queries
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

  // refresh the record before its ttl runs out, so the resolver cache of the name stays warm. ref: false keeps the process free to exit
  async _announce () {
    for await (const records of setInterval(20_000, this._records, { ref: false, signal: this._ctrl.signal })) {
      this._mdns.respond(records)
    }
  }

  // the page opens an event stream on this endpoint. channel.postMessage sends a message on it
  async _serveEvents (id: string, request: IncomingMessage, response: ServerResponse) {
    const channel = this.channel(id)
    response.setHeader('content-type', 'text/event-stream')
    response.setHeader('cache-control', 'no-cache')
    response.setHeader('connection', 'keep-alive')
    // flush the headers, so the page sees an open stream before the first message
    response.flushHeaders()
    channel._attach(response)
    try {
      await once(request, 'close')
    } finally {
      // drop the channel when its last event stream closes
      if (channel._detach(response)) this._channels.delete(id)
    }
  }

  // the page posts a message to this endpoint. the host emits it on the message event of the channel
  async _serveMessage (id: string, request: IncomingMessage, response: ServerResponse) {
    const body = await text(request)

    const channel = this._channels.get(id)
    if (!channel) {
      return send(response, 404)
    }

    try {
      channel.emit('message', JSON.parse(body))
      send(response, 204)
    } catch {
      send(response, 400, 'the request body is not valid json')
    }
  }

  _handleRequest = async (request: IncomingMessage, response: ServerResponse) => {
    cors(request, response)

    // the plain http listener is local only. a request that arrives through the wan port mapper has a public remote address
    if (request.socket.localPort === HTTP_PORT && !isPrivateAddress(request.socket.remoteAddress ?? '')) {
      return send(response, 404)
    }

    if (request.method === 'OPTIONS') return send(response, 204)

    const { pathname } = new URL(request.url ?? '/', `http://${HOSTNAME}`)
    // every page connection uses its own channel. the id is part of the url
    const [route, id] = pathname.split('/').slice(1)

    if (id?.length !== CHANNEL_ID_LENGTH || (route !== 'events' && route !== 'message')) {
      return send(response, 200, { host: HOSTNAME, address: localAddress, port: HTTP_PORT, external: this._external })
    }

    try {
      if (route === 'events' && request.method === 'GET') {
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
}()
