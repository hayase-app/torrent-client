import { networkAddress } from '../network/address'

import type { IncomingMessage, ServerResponse } from 'node:http'

export const HOSTNAME = 'hayase.local'
export const HTTP_PORT = 41734
export const HTTPS_PORT = 41735
export const PROBE_TIMEOUT = 1500
export const ALLOWED_ORIGINS = new Set(['http://localhost:7344', 'https://hayase.app'])
// crypto.randomUUID() returns 36 characters
export const CHANNEL_ID_LENGTH = 36

// reuse the ranked address selection from the torrent client. it may return a bracketed IPv6 address
export const localAddress = networkAddress().replace(/^\[|\]$/g, '')
export const recordType = localAddress.includes(':') ? 'AAAA' : 'A'

export function cors (request: IncomingMessage, response: ServerResponse) {
  const origin = request.headers.origin
  if (!origin || !ALLOWED_ORIGINS.has(origin)) return
  response.setHeader('access-control-allow-origin', origin)
  response.setHeader('vary', 'Origin')
  response.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS')
  response.setHeader('access-control-allow-headers', '*')
}

export function send (response: ServerResponse, status: number, body?: string | Record<string, unknown>) {
  if (typeof body === 'object') {
    response.setHeader('content-type', 'application/json')
    body = JSON.stringify(body)
  }
  response.statusCode = status
  response.end(body)
}

export async function abort <T> (promise: Promise<T>): Promise<T | undefined> {
  try {
    return await promise
  } catch (error) {
    if (!(error instanceof Error) || error.name !== 'AbortError') throw error
  }
}
