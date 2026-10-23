// ===================
// ©AngelaMos | 2026
// events.ts
// ===================

import type { Verdict } from './common.types'
import type { MatchReport } from './intel.types'
import type { NamedFingerprint, StreamEvent } from './stream.types'

export function fingerprintOf(event: StreamEvent): NamedFingerprint {
  switch (event.kind) {
    case 'client_hello':
      return { kind: 'ja4', value: event.ja4.hash }
    case 'server_hello':
      return { kind: 'ja4s', value: event.ja4s.hash }
    case 'certificate':
      return { kind: 'ja4x', value: event.ja4x }
    case 'http_request':
      return { kind: 'ja4h', value: event.ja4h.hash }
    case 'tcp_syn':
      return { kind: 'ja4t', value: event.ja4t }
    case 'tcp_syn_ack':
      return { kind: 'ja4ts', value: event.ja4ts }
  }
}

export function worstVerdict(reports?: MatchReport[]): Verdict | undefined {
  if (!reports || reports.length === 0) return undefined
  const rank: Record<Verdict, number> = {
    malicious: 3,
    suspicious: 2,
    benign: 1,
    unknown: 0,
  }
  return reports.reduce<Verdict>(
    (worst, report) =>
      rank[report.verdict] > rank[worst] ? report.verdict : worst,
    'unknown'
  )
}

export function splitAddr(addr: string): { host: string; port: string } {
  if (addr.startsWith('[')) {
    const close = addr.indexOf(']')
    return { host: addr.slice(1, close), port: addr.slice(close + 2) }
  }
  const colon = addr.lastIndexOf(':')
  if (colon === -1) return { host: addr, port: '' }
  return { host: addr.slice(0, colon), port: addr.slice(colon + 1) }
}

export function formatClock(tsNanos: number): string {
  const date = new Date(tsNanos / 1_000_000)
  const pad = (n: number, width = 2): string => String(n).padStart(width, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(
    date.getSeconds()
  )}.${pad(date.getMilliseconds(), 3)}`
}

export interface Ja4Part {
  field: string
  value: string
  meaning: string
}

const TLS_VERSIONS: Record<string, string> = {
  '13': 'TLS 1.3',
  '12': 'TLS 1.2',
  '11': 'TLS 1.1',
  '10': 'TLS 1.0',
  s3: 'SSL 3.0',
  s2: 'SSL 2.0',
  d1: 'DTLS 1.0',
  d2: 'DTLS 1.2',
  d3: 'DTLS 1.3',
}

const JA4_PATTERN =
  /^([tqd])(\d{2}|[sd][1-3])([di])(\d{2})(\d{2})([0-9a-z]{2})_([0-9a-f]{12})_([0-9a-f]{12})$/

// Splits a JA4 client fingerprint into its documented fields so the detail
// panel can show what each part says. Returns null for anything that is not a
// well-formed JA4 value rather than guessing.
export function decodeJa4(hash: string): Ja4Part[] | null {
  const match = JA4_PATTERN.exec(hash)
  if (!match) return null
  const [
    ,
    transport,
    version,
    sni,
    ciphers,
    extensions,
    alpn,
    cipherHash,
    extHash,
  ] = match
  const transports: Record<string, string> = {
    t: 'TCP',
    q: 'QUIC',
    d: 'DTLS',
  }
  return [
    { field: 'transport', value: transport, meaning: transports[transport] },
    {
      field: 'version',
      value: version,
      meaning: TLS_VERSIONS[version] ?? 'unrecognised',
    },
    {
      field: 'sni',
      value: sni,
      meaning: sni === 'd' ? 'server name present' : 'no server name (or an IP)',
    },
    {
      field: 'ciphers',
      value: ciphers,
      meaning: `${Number(ciphers)} cipher suites`,
    },
    {
      field: 'extensions',
      value: extensions,
      meaning: `${Number(extensions)} extensions`,
    },
    {
      field: 'alpn',
      value: alpn,
      meaning: alpn === '00' ? 'no ALPN offered' : `first ALPN: ${alpn}`,
    },
    {
      field: 'cipher hash',
      value: cipherHash,
      meaning: 'SHA-256 prefix of the sorted cipher list',
    },
    {
      field: 'extension hash',
      value: extHash,
      meaning: 'SHA-256 prefix of sorted extensions and signature algorithms',
    },
  ]
}
