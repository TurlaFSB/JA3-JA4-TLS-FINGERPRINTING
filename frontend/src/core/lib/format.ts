/**
 * © Pranav Verma | 2026
 * format.ts
 */

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

// Bits per second, the unit links are quoted in.
export function formatBitRate(bytesPerSecond: number): string {
  const bits = bytesPerSecond * 8
  if (bits < 1000) return `${Math.round(bits)} bit/s`
  if (bits < 1e6) return `${(bits / 1e3).toFixed(1)} kbit/s`
  if (bits < 1e9) return `${(bits / 1e6).toFixed(1)} Mbit/s`
  return `${(bits / 1e9).toFixed(2)} Gbit/s`
}

export function formatDuration(nanos: number): string {
  const seconds = Math.max(0, nanos / 1e9)
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`
  if (seconds < 60) return `${seconds.toFixed(1)} s`
  if (seconds < 3600)
    return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
}
