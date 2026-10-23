/**
 * © Pranav Verma | 2026
 * library-data.ts
 */

import type { Capture } from '@/api/types'

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

export function formatAge(unixSeconds: number, nowMs: number): string {
  const seconds = Math.max(0, Math.floor(nowMs / 1000 - unixSeconds))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86_400)}d ago`
}

export function matchesCapture(capture: Capture, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (needle === '') return true
  const parts = [
    capture.name,
    capture.headline?.text ?? '',
    ...capture.clients.flatMap((c) => [c.ja4, c.known_as ?? '', ...c.servers]),
  ]
  return parts.join(' ').toLowerCase().includes(needle)
}

export const CONFIDENCE_NOTE = {
  high: 'strong evidence',
  medium: 'moderate evidence',
  low: 'weak evidence',
} as const
