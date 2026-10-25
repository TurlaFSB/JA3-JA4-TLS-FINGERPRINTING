/**
 * © Pranav Verma | 2026
 * stream-data.ts
 */

import type { LiveItem } from '@/api/hooks'
import {
  type Alert,
  type ClientRead,
  fingerprintOf,
  type LiveMessage,
  type MatchReport,
  type Rule,
  type StreamEvent,
  splitAddr,
  type Verdict,
  worstVerdict,
} from '@/api/types'

export type FlowMessage = Extract<LiveMessage, { type: 'flow' }>

export interface FlowItem {
  seq: number
  message: FlowMessage
}

// A TLS connection as the sensor saw it: the ClientHello, the ServerHello, the
// certificate and any cleartext request that belong together.
export interface Connection {
  key: string
  sni?: string
  client?: ClientRead
  ja4?: string
  transport: 'tcp' | 'quic' | 'unknown'
  firstTs: number
  lastTs: number
  items: FlowItem[]
}

const SERVER_SIDE: StreamEvent['kind'][] = [
  'server_hello',
  'certificate',
  'tcp_syn_ack',
]

// Both directions of one connection share a key: server-side events are keyed
// by their addresses reversed.
export function connectionKey(event: StreamEvent): string {
  const serverSide =
    SERVER_SIDE.includes(event.kind) ||
    (event.kind === 'ssh' && event.role === 'server')
  return serverSide ? `${event.dst}>${event.src}` : `${event.src}>${event.dst}`
}

function isFlow(item: LiveItem): item is LiveItem & { message: FlowMessage } {
  return item.message.type === 'flow'
}

export function buildConnections(feed: LiveItem[]): Map<string, Connection> {
  const map = new Map<string, Connection>()
  // The feed is newest first; walk it oldest first so a connection's first
  // event is the one that opens it.
  for (let index = feed.length - 1; index >= 0; index -= 1) {
    const item = feed[index]
    if (!isFlow(item)) continue
    const { event } = item.message
    const key = connectionKey(event)
    let conn = map.get(key)
    if (!conn) {
      conn = {
        key,
        transport: 'unknown',
        firstTs: event.ts_nanos,
        lastTs: event.ts_nanos,
        items: [],
      }
      map.set(key, conn)
    }
    conn.items.push({ seq: item.seq, message: item.message })
    conn.lastTs = Math.max(conn.lastTs, event.ts_nanos)
    conn.firstTs = Math.min(conn.firstTs, event.ts_nanos)
    if (event.kind === 'client_hello') {
      conn.sni = event.sni ?? conn.sni
      conn.ja4 = event.ja4.hash
      conn.transport = event.ja4.hash.startsWith('q') ? 'quic' : 'tcp'
      conn.client = item.message.client ?? conn.client
    } else if (event.kind === 'http_request' && !conn.sni) {
      conn.sni = event.host ?? undefined
    }
  }
  return map
}

const SHORT_FAMILY: Record<string, string> = {
  chromium: 'Chromium',
  firefox: 'Firefox',
  'safari-like': 'Safari-like',
  openssl: 'OpenSSL client',
  library: 'Script / library',
  unknown: 'Unrecognised',
}

export interface ClientName {
  text: string
  basis: 'exact' | 'inferred' | 'none'
}

// The name to put on a row: what the feed says exactly, else the family the
// handshake shape suggests, else nothing.
export function clientName(client?: ClientRead): ClientName {
  if (!client) return { text: '', basis: 'none' }
  if (client.known_as) return { text: client.known_as, basis: 'exact' }
  if (client.family === 'unknown') return { text: 'Unrecognised', basis: 'none' }
  return {
    text: SHORT_FAMILY[client.family] ?? client.family,
    basis: 'inferred',
  }
}

export const NO_NAME = '(no server name)'

export interface SiteClient {
  ja4: string
  name: ClientName
  connections: number
  transport: 'tcp' | 'quic'
}

export interface SiteRow {
  site: string
  connections: number
  clients: SiteClient[]
  lastTs: number
  verdict?: Verdict
  alerts: number
  quic: number
}

const VERDICT_RANK: Record<Verdict, number> = {
  benign: 0,
  unknown: 1,
  suspicious: 2,
  malicious: 3,
}

// One row per server name with the clients that talked to it: the answer to
// "which site was reached by which fingerprint".
export function bySite(feed: LiveItem[]): SiteRow[] {
  const sites = new Map<string, SiteRow>()
  for (const item of feed) {
    if (!isFlow(item)) continue
    const { event } = item.message
    if (event.kind !== 'client_hello') continue
    const site = event.sni ?? NO_NAME
    let row = sites.get(site)
    if (!row) {
      row = { site, connections: 0, clients: [], lastTs: 0, alerts: 0, quic: 0 }
      sites.set(site, row)
    }
    row.connections += 1
    row.lastTs = Math.max(row.lastTs, event.ts_nanos)
    row.alerts += item.message.alerts?.length ?? 0
    const quic = event.ja4.hash.startsWith('q')
    if (quic) row.quic += 1
    const verdict = worstVerdict(item.message.intel)
    if (
      verdict &&
      (row.verdict === undefined ||
        VERDICT_RANK[verdict] > VERDICT_RANK[row.verdict])
    ) {
      row.verdict = verdict
    }
    const existing = row.clients.find((c) => c.ja4 === event.ja4.hash)
    if (existing) {
      existing.connections += 1
    } else {
      row.clients.push({
        ja4: event.ja4.hash,
        name: clientName(item.message.client),
        connections: 1,
        transport: quic ? 'quic' : 'tcp',
      })
    }
  }
  const rows = [...sites.values()]
  for (const row of rows)
    row.clients.sort((a, b) => b.connections - a.connections)
  return rows.sort((a, b) => b.connections - a.connections || b.lastTs - a.lastTs)
}

export function matchesSite(row: SiteRow, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (needle === '') return true
  return (
    row.site.toLowerCase().includes(needle) ||
    row.clients.some(
      (c) =>
        c.ja4.toLowerCase().includes(needle) ||
        c.name.text.toLowerCase().includes(needle)
    )
  )
}

// A short label for the tag on a row, so it says what happened rather than
// only how serious it is.
export const RULE_SHORT: Record<Rule, string> = {
  first_seen: 'new',
  known_bad: 'known bad',
  ua_mismatch: 'ua mismatch',
  os_mismatch: 'os mismatch',
  fp_rotation: 'rotation',
  monoculture: 'monoculture',
  header_anomaly: 'headers',
  custom: 'custom',
  dns_pattern: 'dns',
}

export const RULE_NOTE: Record<Rule, string> = {
  first_seen:
    'This fingerprint had not been recorded before in this database. It is expected on a first run and for any new client or browser update, and it is informational on its own.',
  known_bad:
    'The fingerprint matches an entry the intelligence feed marks as malicious.',
  ua_mismatch:
    'The cleartext User-Agent names one client but the handshake looks like another.',
  os_mismatch:
    'The operating system the User-Agent claims disagrees with the one the TCP/IP stack suggests.',
  fp_rotation:
    'One address presented several different client fingerprints in a short window.',
  monoculture: 'Many addresses presented the identical, unusual fingerprint.',
  header_anomaly:
    'The HTTP request headers are ordered or shaped unlike the client they claim to be.',
  custom: 'A rule written by the operator matched.',
  dns_pattern:
    'A pattern in plain DNS traffic was noticed. See the DNS page for the evidence and what else could explain it.',
}

// The most telling alert on a row: the most severe, then the most recent.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

export function leadAlert(alerts?: Alert[]): Alert | undefined {
  if (!alerts || alerts.length === 0) return undefined
  return alerts.reduce((best, alert) =>
    SEVERITY_RANK[alert.severity] > SEVERITY_RANK[best.severity] ? alert : best
  )
}

// One plain sentence saying what an event is.
export function explain(event: StreamEvent, conn?: Connection): string {
  const src = splitAddr(event.src).host
  const dst = splitAddr(event.dst).host
  const site = conn?.sni
  switch (event.kind) {
    case 'client_hello': {
      const via = event.ja4.hash.startsWith('q')
        ? 'QUIC (HTTP/3)'
        : 'TLS over TCP'
      const target = event.sni ?? dst
      const who = clientName(conn?.client)
      return `${src} started a ${via} connection to ${target}${
        who.basis === 'none'
          ? ''
          : `. The handshake looks like ${who.text}${who.basis === 'inferred' ? ' (inferred from its shape)' : ''}`
      }.`
    }
    case 'server_hello':
      return `${src} answered ${site ? `the connection to ${site}` : `${dst}'s connection`}, choosing the cipher and TLS version the session will use.`
    case 'certificate':
      return `${src} sent its certificate${site ? ` for ${site}` : ''}. The fingerprint describes how the certificate was built, not who issued it.`
    case 'http_request':
      return `${src} sent an unencrypted HTTP ${event.method} request${event.host ? ` to ${event.host}` : ''}. Its header order is fingerprinted.`
    case 'tcp_syn':
      return `${src} opened a TCP connection to ${dst}. The fingerprint describes the operating system's TCP settings.`
    case 'tcp_syn_ack':
      return `${src} accepted the TCP connection from ${dst}. The fingerprint describes the server's TCP settings.`
    case 'ssh':
      return event.role === 'server'
        ? `${src} is an SSH server (${event.banner}). It offered its key exchange, cipher and MAC choices in the clear; HASSH hashes them.`
        : `${src} opened an SSH connection to ${dst} (${event.banner}). Its key exchange, cipher and MAC offer is sent in the clear and is hashed as HASSH${event.role === 'unknown' ? '. The capture did not show which side opened the connection, so both hashes are given' : ''}.`
  }
}

export function intelNote(intel?: MatchReport[]): string {
  return !intel || intel.length === 0
    ? 'No entry in the intelligence feed matches this fingerprint, so its verdict is "unknown". That means it is not catalogued, which is neither a clean nor a bad result.'
    : ''
}

export const EXPORT_HEADERS = [
  'time_utc',
  'kind',
  'src',
  'dst',
  'site',
  'client',
  'fingerprint_kind',
  'fingerprint',
  'verdict',
  'alerts',
]

// The visible stream as spreadsheet rows. Alerts that arrive on their own are
// listed with their title in the kind column.
export function exportRows(
  items: LiveItem[],
  connections: Map<string, Connection>
): (string | number)[][] {
  return items.map((item) => {
    const { message } = item
    if (message.type === 'alert') {
      const alert = message.alert
      return [
        new Date(alert.ts_nanos / 1_000_000).toISOString(),
        `alert:${alert.rule}`,
        alert.ip ?? '',
        '',
        '',
        '',
        alert.fp_kind ?? '',
        alert.fp_value ?? '',
        '',
        1,
      ]
    }
    const { event } = message
    const conn = connections.get(connectionKey(event))
    const fp = fingerprintOf(event)
    const site =
      event.kind === 'client_hello'
        ? (event.sni ?? conn?.sni ?? '')
        : (conn?.sni ?? '')
    return [
      new Date(event.ts_nanos / 1_000_000).toISOString(),
      event.kind,
      event.src,
      event.dst,
      site,
      clientName(message.client ?? conn?.client).text,
      fp.kind,
      fp.value,
      worstVerdict(message.intel) ?? '',
      message.alerts?.length ?? 0,
    ]
  })
}

// The name an event carries itself: the server name a client asked for, or an
// SSH server's software banner. Replies borrow a name from their connection.
export function ownName(event: StreamEvent): string | undefined {
  if (event.kind === 'ssh') return event.banner.replace(/^SSH-[0-9.]+-/, '')
  return 'sni' in event ? event.sni : undefined
}
