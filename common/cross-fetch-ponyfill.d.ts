declare module 'cross-fetch-ponyfill' {
  const fetch: typeof globalThis.fetch

  export default fetch
  export const Blob: typeof globalThis.Blob
  export const File: typeof globalThis.File
  export const FormData: typeof globalThis.FormData
  export const Headers: typeof globalThis.Headers
  export const Request: typeof globalThis.Request
  export const Response: typeof globalThis.Response
  export const AbortController: typeof globalThis.AbortController
  export const AbortSignal: typeof globalThis.AbortSignal
  export const fetch: typeof globalThis.fetch
}
