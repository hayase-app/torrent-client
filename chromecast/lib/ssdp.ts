import dgram from 'node:dgram'
import { EventEmitter, once } from 'node:events'
import os from 'node:os'

const MULTICAST_IP_ADDRESS = '239.255.255.250'
const MULTICAST_PORT = 1900

class Device {
  url
  permanentFallback
  services = [
    'urn:schemas-upnp-org:service:WANIPConnection:1',
    'urn:schemas-upnp-org:service:WANIPConnection:2',
    'urn:schemas-upnp-org:service:WANPPPConnection:1'
  ]

  constructor (opts: { url?: string, permanentFallback?: boolean } = {}) {
    this.url = opts.url
    this.permanentFallback = opts.permanentFallback ?? false
  }
}

export default class Ssdp extends EventEmitter {
  multicast = MULTICAST_IP_ADDRESS
  port = MULTICAST_PORT
  sockets: dgram.Socket[] = []

  _destroyed = false
  _sourcePort
  _bound = false
  _boundCount = 0
  permanentFallback: boolean

  constructor (opts: { sourcePort?: number, permanentFallback?: boolean } = {}) {
    super()

    this._sourcePort = opts.sourcePort ?? 0
    this.permanentFallback = opts.permanentFallback ?? false

    // Create sockets on all external interfaces
    this.createSockets()
  }

  createSockets () {
    if (this._destroyed) throw new Error('client is destroyed')

    const interfaces = os.networkInterfaces()

    this.sockets = []
    for (const key in interfaces) {
      interfaces[key]!.filter((item) => {
        return !item.internal
      }).forEach((item) => {
        this.createSocket(item)
      })
    }
  }

  async search (device: string, timeoutms: number) {
    if (this._destroyed) throw new Error('client is destroyed')

    await this._waitForBind()

    const query = Buffer.from(
      'M-SEARCH * HTTP/1.1\r\n' +
      'HOST: ' + this.multicast + ':' + this.port + '\r\n' +
      'MAN: "ssdp:discover"\r\n' +
      'MX: 1\r\n' +
      'ST: ' + device + '\r\n' +
      '\r\n'
    )

    const timeout = new Promise<[Record<string, string>, string]>((resolve, reject) => {
      setTimeout(() => {
        const err = new Error('timeout')
        reject(err)
      }, timeoutms).unref?.()
    })

    const event = once(this, '_device') as Promise<[Record<string, string>, string]>

    this.sockets.forEach((socket) => {
      socket.send(query, 0, query.length, this.port, this.multicast)
    })

    try {
      const [info, address] = await Promise.race([event, timeout])

      if (info.st !== device) return {}

      return { device: new Device({ url: info.location, permanentFallback: this.permanentFallback }), address }
    } catch (error) {
      return {}
    }
  }

  createSocket (interf: os.NetworkInterfaceInfo) {
    if (this._destroyed) throw new Error('client is destroyed')

    let socket = dgram.createSocket(interf.family === 'IPv4' ? 'udp4' : 'udp6')

    socket.on('message', (message) => {
      // Ignore messages after closing sockets
      if (this._destroyed) return

      // Parse response
      this._parseResponse(message.toString(), socket.address)
    })

    // Unqueue this._queue once all sockets are ready
    const onReady = () => {
      if (this._boundCount < this.sockets.length) return

      this._bound = true
    }

    socket.on('listening', () => {
      this._boundCount += 1
      onReady()
    })

    const onClose = () => {
      if (socket) {
        const index = this.sockets.indexOf(socket)
        this.sockets.splice(index, 1)
        socket = null!
      }
    }

    // On error - remove socket from list and execute items from queue
    socket.on('close', () => {
      onClose()
    })
    socket.on('error', () => {
      // Ignore errors

      if (socket) {
        socket.close()
        // Force trigger onClose() - 'close()' does not guarantee to emit 'close'
        onClose()
      }

      onReady()
    })

    socket.address = interf.address
    socket.bind(this._sourcePort, interf.address)

    this.sockets.push(socket)
  }

  // TODO create separate logic for parsing unsolicited upnp broadcasts,
  // if and when that need arises
  _parseResponse (response: string, addr: string) {
    if (this._destroyed) return

    // Ignore incorrect packets
    if (!/^(HTTP|NOTIFY)/m.test(response)) return

    const headers = this._parseMimeHeader(response)

    // Messages that match the original search target
    if (!headers?.st) return

    this.emit('_device', headers, addr)
  }

  _parseMimeHeader (headerStr: string) {
    if (this._destroyed) return

    const lines = headerStr.split(/\r\n/g)

    // Parse headers from lines to hashmap
    return lines.reduce<Record<string, string>>((headers, line) => {
      line.replace(/^([^:]*)\s*:\s*(.*)$/, (a, key, value) => {
        headers[key.toLowerCase()] = value
      })
      return headers
    }, {})
  }

  _waitForBind () {
    return new Promise<void>((resolve, reject) => {
      if (!this._bound) {
        const removeListeners = () => {
          this.sockets.forEach((socket) => {
            socket.removeListener('listening', resolveTrue)
          })
        }

        const resolveTrue = () => {
          clearTimeout(timeout)
          removeListeners()
          resolve()
        }
        const timeout = setTimeout(() => {
          removeListeners()
          reject(new Error('timeout'))
        }, 5000)

        this.sockets.forEach((socket) => {
          socket.on('listening', resolveTrue)
        })
      } else {
        resolve()
      }
    })
  }

  async destroy () {
    this._destroyed = true

    return await Promise.allSettled(this.sockets.map(socket => new Promise<void>(resolve => socket.close(resolve))))
  }
}
