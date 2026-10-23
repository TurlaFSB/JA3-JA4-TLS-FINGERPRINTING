/**
 * © Pranav Verma | 2026
 * profile-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { LiveItem } from '@/api/hooks'
import { compare, summarise, timeline } from './profile-data'

const RAW_A = 't13d1516h2_1301,1302,c02b_0005,000a,fe0d_0403,0804'
const RAW_B = 't13d1517h2_1301,1303,c02b_0005,000a,001b_0403,0804'

function hello(
  seq: number,
  ja4: string,
  raw: string,
  sni: string,
  verdict: 'benign' | 'unknown' = 'unknown',
  ts = seq * 1_000_000_000
): LiveItem {
  return {
    seq,
    animate: false,
    message: {
      type: 'flow',
      event: {
        kind: 'client_hello',
        ts_nanos: ts,
        src: '10.0.0.5:50000',
        dst: '203.0.113.9:443',
        ja3: `ja3-${seq}`,
        ja3_raw: '',
        ja4: { hash: ja4, raw },
        sni,
        alpn: 'h2',
      },
      intel:
        verdict === 'benign'
          ? [
              {
                kind: 'ja4',
                observed: ja4,
                verdict,
                threat_score: 0,
                confidence: 1,
                hits: [
                  {
                    kind: 'ja4',
                    value: ja4,
                    label: 'Example Browser',
                    category: 'benign',
                    source: 'test',
                    strength: 'exact',
                  },
                ],
              },
            ]
          : [],
      alerts: [],
    },
  }
}

describe('summarise', () => {
  const feed = [
    hello(1, 'ja4-a', RAW_A, 'one.test', 'benign'),
    hello(2, 'ja4-a', RAW_A, 'two.test', 'benign'),
    hello(3, 'ja4-b', RAW_B, 'one.test'),
  ]

  it('groups client hellos by fingerprint, busiest first', () => {
    const { fingerprints } = summarise(feed)
    expect(fingerprints.map((f) => f.ja4)).toEqual(['ja4-a', 'ja4-b'])
    expect(fingerprints[0].connections).toBe(2)
    expect(fingerprints[0].labels).toEqual(['Example Browser'])
    expect(fingerprints[0].verdict).toBe('benign')
    expect(fingerprints[1].verdict).toBe('unknown')
  })

  it('groups by server name and counts distinct fingerprints', () => {
    const { destinations } = summarise(feed)
    const one = destinations.find((d) => d.name === 'one.test')
    expect(one?.connections).toBe(2)
    expect(one?.fingerprints.size).toBe(2)
  })

  it('ignores everything that is not a client hello', () => {
    const syn: LiveItem = {
      seq: 9,
      animate: false,
      message: {
        type: 'flow',
        event: {
          kind: 'tcp_syn',
          ts_nanos: 1,
          src: '10.0.0.5:1',
          dst: '10.0.0.6:2',
          ja4t: 'x',
        },
      },
    }
    expect(summarise([syn]).fingerprints).toEqual([])
  })
})

describe('timeline', () => {
  it('places every connection in exactly one bucket', () => {
    const buckets = timeline([0, 10, 10, 100], 4)
    expect(buckets.reduce((sum, b) => sum + b.count, 0)).toBe(4)
    expect(buckets[0].count).toBe(3)
    expect(buckets[3].count).toBe(1)
  })

  it('handles a single instant', () => {
    expect(timeline([5, 5], 4)[0].count).toBe(2)
    expect(timeline([])).toEqual([])
  })
})

describe('compare', () => {
  it('lists what is in only one of two client hellos', () => {
    const [a, b] = summarise([
      hello(1, 'ja4-a', RAW_A, 'one.test'),
      hello(2, 'ja4-b', RAW_B, 'one.test'),
    ]).fingerprints
    const diff = compare(a, b)
    expect(diff.ciphers.onlyA).toEqual(['TLS_AES_256_GCM_SHA384 (1302)'])
    expect(diff.ciphers.onlyB).toEqual(['TLS_CHACHA20_POLY1305_SHA256 (1303)'])
    expect(diff.extensions.onlyA).toEqual(['encrypted_client_hello (fe0d)'])
    expect(diff.extensions.onlyB).toEqual(['compress_certificate (001b)'])
    expect(diff.signatures.onlyA).toEqual([])
    expect(diff.sharedDestinations).toEqual(['one.test'])
  })
})
