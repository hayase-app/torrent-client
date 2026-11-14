import { statfs, access, mkdir, constants } from 'node:fs/promises'
import { dirname } from 'node:path'

export * from './chunkStore.ts'

export async function checkAvailableSpace (path: string) {
  try {
    const { bsize, bavail } = await statfs(path)
    return bsize * bavail
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT') {
      let current = path
      while (current && current !== dirname(current)) {
        current = dirname(current)
        try {
          const { bsize, bavail } = await statfs(current)
          return bsize * bavail
        } catch {}
      }
    }
    throw err
  }
}

export async function verifyDirectoryPermissions (path: string, fallback: string) {
  const target = path || fallback
  try {
    await mkdir(target, { recursive: true })
    await access(target, constants.R_OK | constants.W_OK)
  } catch {
    throw new Error(`Insufficient permissions to access directory: ${target}`)
  }
}
