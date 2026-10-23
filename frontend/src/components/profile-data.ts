/**
 * © Pranav Verma | 2026
 * profiles.ts
 */

import type { LiveItem } from '@/api/hooks'
import { splitAddr, type Verdict, worstVerdict } from '@/api/types'

const RANK: Record<Verdict, number> = {
  malicious: 3,
  suspicious: 2,
  benign: 1,
  unknown: 0,
}

function worse(a: Verdict, b: Verdict): Verdict {
  return RANK[b] > RANK[a] ? b : a
}

function bump(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1)
}

export interface FingerprintProfile {
  ja4: string
  raw: string
  connections: number
  verdict: Verdict
  // Labels of exact intelligence matches, the only ones that name a client.
  labels: string[]
  destinations: Map<string, number>
  sources: Map<string, number>
  ja3: Set<string>
  alpn: Set<string>
  alerts: number
  times: number[]
  firstNanos: number
  lastNanos: number
}

export interface DestinationProfile {
  name: string
  connections: number
  verdict: Verdict
  fingerprints: Map<string, number>
  sources: Set<string>
  lastNanos: number
}

export interface Profiles {
  fingerprints: FingerprintProfile[]
  destinations: DestinationProfile[]
}

// Summarises the client hellos in the live window by fingerprint and by the
// server name they asked for. Pure and recomputed from the feed, so it can
// never disagree with the stream beside it.
export function summarise(feed: LiveItem[]): Profiles {
  const fingerprints = new Map<string, FingerprintProfile>()
  const destinations = new Map<string, DestinationProfile>()

  for (const { message } of feed) {
    if (message.type !== 'flow' || message.event.kind !== 'client_hello') {
      continue
    }
    const { event } = message
    const verdict = worstVerdict(message.intel) ?? 'unknown'
    const host = splitAddr(event.src).host
    const target = event.sni ?? splitAddr(event.dst).host

    let fp = fingerprints.get(event.ja4.hash)
    if (!fp) {
      fp = {
        ja4: event.ja4.hash,
        raw: event.ja4.raw,
        connections: 0,
        verdict: 'unknown',
        labels: [],
        destinations: new Map(),
        sources: new Map(),
        ja3: new Set(),
        alpn: new Set(),
        alerts: 0,
        times: [],
        firstNanos: event.ts_nanos,
        lastNanos: event.ts_nanos,
      }
      fingerprints.set(event.ja4.hash, fp)
    }
    fp.connections += 1
    fp.times.push(event.ts_nanos)
    fp.verdict = worse(fp.verdict, verdict)
    fp.firstNanos = Math.min(fp.firstNanos, event.ts_nanos)
    fp.lastNanos = Math.max(fp.lastNanos, event.ts_nanos)
    fp.ja3.add(event.ja3)
    if (event.alpn) fp.alpn.add(event.alpn)
    fp.alerts += message.alerts?.length ?? 0
    bump(fp.destinations, target)
    bump(fp.sources, host)
    for (const report of message.intel ?? []) {
      for (const hit of report.hits) {
        if (hit.strength === 'exact' && !fp.labels.includes(hit.label)) {
          fp.labels.push(hit.label)
        }
      }
    }

    let dest = destinations.get(target)
    if (!dest) {
      dest = {
        name: target,
        connections: 0,
        verdict: 'unknown',
        fingerprints: new Map(),
        sources: new Set(),
        lastNanos: event.ts_nanos,
      }
      destinations.set(target, dest)
    }
    dest.connections += 1
    dest.verdict = worse(dest.verdict, verdict)
    dest.lastNanos = Math.max(dest.lastNanos, event.ts_nanos)
    bump(dest.fingerprints, event.ja4.hash)
    dest.sources.add(host)
  }

  const byCount = <T extends { connections: number }>(a: T, b: T): number =>
    b.connections - a.connections
  return {
    fingerprints: [...fingerprints.values()].sort(byCount),
    destinations: [...destinations.values()].sort(byCount),
  }
}

export function topEntries(
  map: Map<string, number>,
  limit: number
): [string, number][] {
  return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit)
}

function csvCell(value: string | number): string {
  const text = String(value)
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text
}

export function fingerprintsCsv(rows: FingerprintProfile[]): string {
  const head = 'ja4,connections,verdict,labels,destinations,sources,ja3_variants'
  const lines = rows.map((r) =>
    [
      r.ja4,
      r.connections,
      r.verdict,
      r.labels.join('; '),
      r.destinations.size,
      r.sources.size,
      r.ja3.size,
    ]
      .map(csvCell)
      .join(',')
  )
  return [head, ...lines].join('\n')
}

export function destinationsCsv(rows: DestinationProfile[]): string {
  const head = 'destination,connections,verdict,distinct_fingerprints,sources'
  const lines = rows.map((r) =>
    [r.name, r.connections, r.verdict, r.fingerprints.size, r.sources.size]
      .map(csvCell)
      .join(',')
  )
  return [head, ...lines].join('\n')
}

export function download(name: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = name
  anchor.click()
  URL.revokeObjectURL(url)
}

export const VERDICT_NOTE: Record<Verdict, string> = {
  unknown:
    'No exact match in the intelligence feed. Neither vouched for nor accused.',
  benign:
    'Matches a fingerprint the feed lists as benign. A tool that reproduces it byte for byte shares this verdict.',
  suspicious: 'Matches a fingerprint the feed lists as suspicious.',
  malicious: 'Matches a fingerprint the feed lists as malicious.',
}

// Connection counts in equal time slices from first to last sighting.
export interface Bucket {
  id: number
  count: number
}

export function timeline(times: number[], buckets = 32): Bucket[] {
  if (times.length === 0) return []
  const first = Math.min(...times)
  const last = Math.max(...times)
  const counts = Array.from({ length: buckets }, () => 0)
  const span = last - first
  for (const t of times) {
    const index =
      span === 0
        ? 0
        : Math.min(buckets - 1, Math.floor(((t - first) / span) * buckets))
    counts[index] += 1
  }
  return counts.map((count, id) => ({ id, count }))
}

const EXTENSION_NAMES: Record<string, string> = {
  '0005': 'status_request',
  '000a': 'supported_groups',
  '000b': 'ec_point_formats',
  '000d': 'signature_algorithms',
  '0012': 'signed_certificate_timestamp',
  '0015': 'padding',
  '0017': 'extended_master_secret',
  '001b': 'compress_certificate',
  '0022': 'delegated_credentials',
  '0023': 'session_ticket',
  '0029': 'pre_shared_key',
  '002b': 'supported_versions',
  '002d': 'psk_key_exchange_modes',
  '0033': 'key_share',
  '4469': 'alps (legacy codepoint)',
  '44cd': 'alps (new codepoint)',
  fe0d: 'encrypted_client_hello',
  ff01: 'renegotiation_info',
  ca34: 'trust_anchors',
}

const CIPHER_NAMES: Record<string, string> = {
  '1301': 'TLS_AES_128_GCM_SHA256',
  '1302': 'TLS_AES_256_GCM_SHA384',
  '1303': 'TLS_CHACHA20_POLY1305_SHA256',
  c02b: 'ECDHE_ECDSA_AES_128_GCM',
  c02c: 'ECDHE_ECDSA_AES_256_GCM',
  c02f: 'ECDHE_RSA_AES_128_GCM',
  c030: 'ECDHE_RSA_AES_256_GCM',
  cca8: 'ECDHE_RSA_CHACHA20',
  cca9: 'ECDHE_ECDSA_CHACHA20',
  c013: 'ECDHE_RSA_AES_128_CBC_SHA',
  c014: 'ECDHE_RSA_AES_256_CBC_SHA',
  '009c': 'RSA_AES_128_GCM',
  '009d': 'RSA_AES_256_GCM',
  '002f': 'RSA_AES_128_CBC_SHA',
  '0035': 'RSA_AES_256_CBC_SHA',
}

export interface ListDiff {
  onlyA: string[]
  onlyB: string[]
  both: number
}

function diffLists(
  a: string[],
  b: string[],
  names: Record<string, string>
): ListDiff {
  const setA = new Set(a)
  const setB = new Set(b)
  const label = (code: string): string =>
    names[code] ? `${names[code]} (${code})` : code
  return {
    onlyA: a.filter((x) => !setB.has(x)).map(label),
    onlyB: b.filter((x) => !setA.has(x)).map(label),
    both: a.filter((x) => setB.has(x)).length,
  }
}

function rawParts(raw: string): [string[], string[], string[]] {
  const [, ciphers = '', extensions = '', signatures = ''] = raw.split('_')
  const list = (csv: string): string[] => (csv ? csv.split(',') : [])
  return [list(ciphers), list(extensions), list(signatures)]
}

export interface Comparison {
  ciphers: ListDiff
  extensions: ListDiff
  signatures: ListDiff
  sharedDestinations: string[]
}

// What differs between two client hellos, read from the JA4 raw strings. The
// extension list excludes server name and ALPN by the JA4 specification.
export function compare(
  a: FingerprintProfile,
  b: FingerprintProfile
): Comparison {
  const [ca, ea, sa] = rawParts(a.raw)
  const [cb, eb, sb] = rawParts(b.raw)
  return {
    ciphers: diffLists(ca, cb, CIPHER_NAMES),
    extensions: diffLists(ea, eb, EXTENSION_NAMES),
    signatures: diffLists(sa, sb, {}),
    sharedDestinations: [...a.destinations.keys()].filter((d) =>
      b.destinations.has(d)
    ),
  }
}
