/**
 * © Pranav Verma | 2026
 * traffic-data.ts
 */

import { splitAddr, type TrafficFlow } from '@/api/types'
import { formatBytes, formatDuration } from '@/core/lib/format'

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
    flow.http_host ?? '',
    flow.client_host?.name ?? '',
    flow.server_host?.name ?? '',
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

export const FLOW_HEADERS = [
  'first_seen_utc',
  'last_seen_utc',
  'protocol',
  'service',
  'direction',
  'client',
  'server',
  'server_name',
  'name_source',
  'client_identity',
  'ja4',
  'bytes_up',
  'bytes_down',
  'packets_up',
  'packets_down',
  'state',
]

// The conversations as spreadsheet rows, with where each server name came from.
export function flowRows(flows: TrafficFlow[]): (string | number)[][] {
  const iso = (ns: number): string => new Date(ns / 1e6).toISOString()
  return flows.map((flow) => {
    const site = siteName(flow)
    return [
      iso(flow.first_ns),
      iso(flow.last_ns),
      flow.proto,
      flow.service ?? '',
      flow.direction,
      flow.client,
      flow.server,
      site.name,
      site.name === '' ? '' : site.viaDns ? 'dns' : 'handshake',
      identity(flow),
      flow.ja4 ?? '',
      flow.bytes_up,
      flow.bytes_down,
      flow.packets_up,
      flow.packets_down,
      flow.state,
    ]
  })
}

export interface Endpoint {
  /** What to show first: a name when one is known, else the address. */
  primary: string
  /** The address and port. */
  secondary: string
  /** How the name is known, so a reader can judge it. */
  tag: string
}

function portOf(addr: string): string {
  return splitAddr(addr).port
}

function hostOf(addr: string): string {
  return splitAddr(addr).host
}

// The side that opened the conversation.
export function clientEndpoint(flow: TrafficFlow): Endpoint {
  const host = flow.client_host
  return {
    primary: host?.name ?? hostOf(flow.client),
    secondary: `${hostOf(flow.client)}:${portOf(flow.client)}`,
    tag: host?.source ?? '',
  }
}

// The side that answered, named from the best evidence there is: the name the
// handshake asked for, the HTTP Host header, a DNS answer, a reverse lookup.
export function serverEndpoint(flow: TrafficFlow): Endpoint {
  const secondary = `${hostOf(flow.server)}:${portOf(flow.server)}`
  if (flow.sni) {
    return { primary: flow.sni, secondary, tag: 'tls handshake' }
  }
  if (flow.http_host) {
    return { primary: flow.http_host, secondary, tag: 'http request' }
  }
  if (flow.dns_name) {
    return { primary: flow.dns_name, secondary, tag: 'dns answer' }
  }
  if (flow.server_host) {
    return {
      primary: flow.server_host.name,
      secondary,
      tag: flow.server_host.source,
    }
  }
  return {
    primary: hostOf(flow.server),
    secondary: `port ${portOf(flow.server)}`,
    tag: '',
  }
}

const SERVICE_WORDS: Record<string, string> = {
  https: 'an HTTPS connection',
  http: 'an HTTP connection',
  quic: 'a QUIC (HTTP/3) session',
  dns: 'a DNS exchange',
  ssh: 'an SSH session',
  'dns-over-tls': 'an encrypted DNS connection',
  imaps: 'a secure mail connection',
  smtp: 'a mail connection',
  rdp: 'a remote desktop session',
  smb: 'a file-sharing connection',
  ntp: 'a time-sync exchange',
  mdns: 'a local name-discovery exchange',
  ssdp: 'a local device-discovery exchange',
  dhcp: 'an address-lease exchange',
  wireguard: 'a WireGuard tunnel',
}

// What kind of conversation this is, in a few words: the service, then what the
// handshake revealed about the protocol.
export function protocolWords(flow: TrafficFlow): string {
  const parts: string[] = [(flow.service ?? flow.proto).toUpperCase()]
  if (flow.tls_version) parts.push(flow.tls_version)
  else if (flow.ja4) parts.push('TLS')
  if (flow.alpn) parts.push(flow.alpn)
  if (flow.ssh_banner) parts.push(flow.ssh_banner.replace(/^SSH-[0-9.]+-/, ''))
  if (flow.http_method) parts.push(flow.http_method)
  return parts.join(' · ')
}

// One plain sentence about the conversation.
export function describeFlow(flow: TrafficFlow): string {
  const from = clientEndpoint(flow)
  const to = serverEndpoint(flow)
  const fromText =
    from.primary === hostOf(flow.client)
      ? from.primary
      : `${from.primary} (${hostOf(flow.client)})`
  const toText =
    to.primary === hostOf(flow.server)
      ? to.primary
      : `${to.primary} (${hostOf(flow.server)})`
  const what =
    (flow.service ? SERVICE_WORDS[flow.service] : undefined) ??
    `a ${flow.proto.toUpperCase()} conversation`
  const who = flow.client_info
    ? flow.client_info.known_as
      ? ` The client is ${flow.client_info.known_as}.`
      : flow.client_info.family !== 'unknown'
        ? ` The client looks like ${flow.client_info.family} (inferred from its handshake).`
        : ''
    : ''
  return `${fromText} opened ${what} to ${toText} on port ${portOf(flow.server)}. It sent ${formatBytes(flow.bytes_up)} and received ${formatBytes(flow.bytes_down)} over ${formatDuration(flow.last_ns - flow.first_ns)}.${who}`
}
