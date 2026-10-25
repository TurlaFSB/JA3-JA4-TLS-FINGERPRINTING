/**
 * © Pranav Verma | 2026
 * traffic-data.ts
 */

import type { TrafficFlow } from '@/api/types'

export type DirectionFilter = 'all' | TrafficFlow['direction']
export type ProtoFilter = 'all' | TrafficFlow['proto']
export type SortKey = 'recent' | 'bytes' | 'duration'

export interface FlowFilter {
  direction: DirectionFilter
  proto: ProtoFilter
  namedOnly: boolean
  query: string
}

export function flowBytes(flow: TrafficFlow): number {
  return flow.bytes_up + flow.bytes_down
}

// The name to show for a conversation's server: the one its handshake asked
// for, else the one DNS gave its address.
export function siteName(flow: TrafficFlow): {
  name: string
  viaDns: boolean
} {
  if (flow.sni) return { name: flow.sni, viaDns: false }
  if (flow.dns_name) return { name: flow.dns_name, viaDns: true }
  return { name: '', viaDns: false }
}

export function identity(flow: TrafficFlow): string {
  return flow.client_info?.known_as ?? flow.client_info?.family ?? ''
}

export function matchesFlow(flow: TrafficFlow, filter: FlowFilter): boolean {
  if (filter.direction !== 'all' && flow.direction !== filter.direction) {
    return false
  }
  if (filter.proto !== 'all' && flow.proto !== filter.proto) return false
  if (filter.namedOnly && !flow.sni && !flow.dns_name) return false
  const needle = filter.query.trim().toLowerCase()
  if (needle === '') return true
  const haystack = [
    flow.client,
    flow.server,
    flow.sni ?? '',
    flow.dns_name ?? '',
    flow.service ?? '',
    flow.ja4 ?? '',
    identity(flow),
  ]
    .join(' ')
    .toLowerCase()
  return haystack.includes(needle)
}

export function sortFlows(flows: TrafficFlow[], key: SortKey): TrafficFlow[] {
  const copy = [...flows]
  if (key === 'bytes') copy.sort((a, b) => flowBytes(b) - flowBytes(a))
  else if (key === 'duration') {
    copy.sort((a, b) => b.last_ns - b.first_ns - (a.last_ns - a.first_ns))
  } else copy.sort((a, b) => b.last_ns - a.last_ns)
  return copy
}

export const DIRECTION_ARROW: Record<TrafficFlow['direction'], string> = {
  outbound: '↑',
  inbound: '↓',
  internal: '↔',
  transit: '⇄',
}

export const DIRECTION_NOTE: Record<TrafficFlow['direction'], string> = {
  outbound: 'a local host opened this connection to a remote one',
  inbound: 'a remote host opened this connection to a local one',
  internal: 'both ends are on local networks',
  transit: 'neither end is on a local network',
}

// A shared scale for the in and out series so the two lines compare honestly.
export function chartMax(values: number[]): number {
  const peak = Math.max(0, ...values)
  if (peak === 0) return 1
  const magnitude = 10 ** Math.floor(Math.log10(peak))
  return Math.ceil(peak / magnitude) * magnitude
}

export function linePath(
  values: number[],
  width: number,
  height: number,
  max: number
): string {
  if (values.length === 0) return ''
  const step = values.length > 1 ? width / (values.length - 1) : 0
  return values
    .map((value, index) => {
      const x = (index * step).toFixed(1)
      const y = (height - (value / max) * height).toFixed(1)
      return `${index === 0 ? 'M' : 'L'}${x} ${y}`
    })
    .join(' ')
}
