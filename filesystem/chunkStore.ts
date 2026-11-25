import FSChunkStore from 'fs-chunk-store'

const WINDOWS_RESERVED_CHARS = /[<>:"/\\|?*]/g
const WINDOWS_TRAILING = /[. ]+$/

export function sanitizeWindowsSegment (segment: string): string {
  if (process.platform !== 'win32') return segment
  return segment.replace(WINDOWS_RESERVED_CHARS, '-').replace(WINDOWS_TRAILING, '')
}

export function sanitizeWindowsPath (filePath: string): string {
  if (process.platform !== 'win32') return filePath
  return filePath
    .split(/[/\\]/)
    .map(sanitizeWindowsSegment)
    .filter(Boolean)
    .join('/')
}

export class SafeFSChunkStore extends FSChunkStore {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor (chunkLength: number, opts: any = {}) {
    if (process.platform === 'win32' && opts) {
      if (typeof opts.name === 'string') {
        opts.name = sanitizeWindowsSegment(opts.name)
      }
      if (Array.isArray(opts.files)) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        opts.files = opts.files.map((file: any) => ({
          ...file,
          path: typeof file.path === 'string' ? sanitizeWindowsPath(file.path) : file.path
        }))
      }
    }
    super(chunkLength, opts)
  }
}
