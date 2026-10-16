import { arr2hex, arr2text, concat, randomBytes, text2arr } from 'uint8-util'

import { networkAddress } from '../network/address.ts'

import type { Http2ServerRequest, Http2ServerResponse } from 'node:http2'

export const HOSTNAME = 'hayase.local'
export const PROBE_TIMEOUT = 1500
// the port is fixed, so a browser can find the host. HAYASE_PORT overrides it
export const PORT = Number(process.env.HAYASE_PORT) || 41734
export const ALLOWED_ORIGINS = new Set(['http://localhost:7344', 'https://hayase.app'])
// crypto.randomUUID() returns 36 characters
export const CHANNEL_ID_LENGTH = 36

// reuse the ranked address selection from the torrent client. it may return a bracketed IPv6 address
export const localAddress = networkAddress().replace(/^\[|\]$/g, '')
export const recordType = localAddress.includes(':') ? 'AAAA' : 'A'

const pinnedKey = process.env.HAYASE_KEY?.trim()
export const HOST_KEY = pinnedKey?.length ? pinnedKey : arr2hex(randomBytes(32))

const secret = crypto.subtle.importKey('raw', text2arr(HOST_KEY), 'HKDF', false, ['deriveKey'])

export async function channelKey (id: string) {
  return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: text2arr(id), info: text2arr(HOSTNAME) }, await secret, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

export async function encrypt (key: CryptoKey, message: unknown) {
  const iv = randomBytes(12)
  return concat([iv, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, text2arr(JSON.stringify(message))))])
}

export async function decrypt (key: CryptoKey, message: Uint8Array): Promise<unknown> {
  return JSON.parse(arr2text(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: message.slice(0, 12) }, key, message.slice(12))))
}

export function cors (request: Http2ServerRequest, response: Http2ServerResponse) {
  const origin = request.headers.origin
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return
  response.setHeader('access-control-allow-origin', origin)
  response.setHeader('vary', 'Origin')
  response.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS')
  response.setHeader('access-control-allow-headers', '*')
}

export function send (response: Http2ServerResponse, status: number, body?: string | Record<string, unknown>) {
  if (typeof body === 'object') {
    response.setHeader('content-type', 'application/json')
    body = JSON.stringify(body)
  }
  response.statusCode = status
  response.end(body ?? '')
}

export async function abort <T> (promise: Promise<T>): Promise<T | undefined> {
  try {
    return await promise
  } catch (error) {
    if (!(error instanceof Error) || error.name !== 'AbortError') throw error
  }
}
