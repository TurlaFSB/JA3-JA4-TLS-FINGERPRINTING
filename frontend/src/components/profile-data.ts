/**
 * ©AngelaMos | 2026
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
        firstNanos: event.ts_nanos,
        lastNanos: event.ts_nanos,
      }
      fingerprints.set(event.ja4.hash, fp)
    }
    fp.connections += 1
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
