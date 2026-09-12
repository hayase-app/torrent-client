import { statfs, access, constants } from 'node:fs/promises'

export async function checkAvailableSpace (path: string) {
  const { bsize, bavail } = await statfs(path)
  return bsize * bavail
}

export async function verifyDirectoryPermissions (path: string, fallback: string) {
  try {
    await access(path || fallback, constants.R_OK | constants.W_OK)
  } catch {
    throw new Error(`Insufficient permissions to access directory: ${path}`)
  }
}
