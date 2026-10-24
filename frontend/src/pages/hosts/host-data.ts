/**
 * © Pranav Verma | 2026
 * host-data.ts
 */

import type { ClientSpan, HostSummary } from '@/api/types'
import { formatDuration } from '@/core/lib/format'

export interface Bar {
  left: number
  width: number
}

// Where each client's life sits on the host's timeline, as percentages. A
// client seen at a single instant still gets a visible sliver.
export function barFor(
  client: ClientSpan,
  start: number,
  end: number,
  minWidth = 0.8
): Bar {
  const span = end - start
  if (span <= 0) return { left: 0, width: 100 }
  const left = ((client.first_ts - start) / span) * 100
  const width = Math.max(
    minWidth,
    ((client.last_ts - client.first_ts) / span) * 100
  )
  const clampedLeft = Math.min(left, 100 - minWidth)
  return { left: clampedLeft, width: Math.min(width, 100 - clampedLeft) }
}

export function appeared(client: ClientSpan, hostFirst: number): string {
  const offset = client.first_ts - hostFirst
  return offset <= 0
    ? 'with the first sighting'
    : `${formatDuration(offset)} after the first sighting`
}

// The clients that appeared after the host was first seen: the ones that mark
// a change in what the host runs.
export function laterClients(clients: ClientSpan[]): ClientSpan[] {
  return [...clients].sort((a, b) => a.first_ts - b.first_ts).slice(1)
}

export function whenText(nanos: number): string {
  return new Date(nanos / 1_000_000).toLocaleString()
}

export type HostSort = 'recent' | 'clients' | 'alerts'

export function sortHosts(hosts: HostSummary[], key: HostSort): HostSummary[] {
  const copy = [...hosts]
  if (key === 'clients')
    copy.sort((a, b) => b.clients - a.clients || b.last_ts - a.last_ts)
  else if (key === 'alerts')
    copy.sort((a, b) => b.alerts - a.alerts || b.last_ts - a.last_ts)
  else copy.sort((a, b) => b.last_ts - a.last_ts)
  return copy
}

export function matchesHost(host: HostSummary, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (needle === '') return true
  return `${host.ip} ${host.top_label ?? ''}`.toLowerCase().includes(needle)
}
