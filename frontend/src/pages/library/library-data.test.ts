/**
 * © Pranav Verma | 2026
 * library-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { Capture } from '@/api/types'
import { formatAge, formatBytes, matchesCapture } from './library-data'

const capture = (over: Partial<Capture>): Capture => ({
  id: 'x',
  name: 'edge.pcapng',
  size: 10,
  modified_unix: 0,
  status: 'ready',
  error: null,
  frames: 1,
  tls_handshakes: 1,
  quic_initials: 0,
  first_ts_nanos: null,
  last_ts_nanos: null,
  clients: [],
  headline: null,
  ...over,
})

describe('formatting', () => {
  it('scales byte counts', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KB')
    expect(formatBytes(5 * 1024 ** 2)).toBe('5.0 MB')
  })

  it('describes age without going negative', () => {
    expect(formatAge(100, 130_000)).toBe('30s ago')
    expect(formatAge(100, (100 + 7200) * 1000)).toBe('2h ago')
    expect(formatAge(500, 100_000)).toBe('0s ago')
  })
})

describe('matchesCapture', () => {
  it('matches the file name, the identification and the servers', () => {
    const c = capture({
      headline: {
        ja4: 'a',
        text: 'Firefox 158',
        basis: 'exact',
        confidence: 'high',
        caveat: null,
      },
      clients: [
        {
          ja4: 't13d1517h2_x',
          transport: 'tcp',
          connections: 2,
          ja3_variants: 1,
          alpn: 'h2',
          servers: ['example.com'],
          known_as: null,
          verdict: null,
          guess: {
            family: 'firefox',
            confidence: 'high',
            reasons: [],
            caveat: null,
          },
        },
      ],
    })
    expect(matchesCapture(c, 'EDGE')).toBe(true)
    expect(matchesCapture(c, 'firefox')).toBe(true)
    expect(matchesCapture(c, 'example.com')).toBe(true)
    expect(matchesCapture(c, 't13d1517')).toBe(true)
    expect(matchesCapture(c, 'nothing')).toBe(false)
    expect(matchesCapture(c, '  ')).toBe(true)
  })
})
