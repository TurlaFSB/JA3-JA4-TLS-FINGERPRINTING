/**
 * © Pranav Verma | 2026
 * stream-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { LiveItem } from '@/api/hooks'
import type { ClientRead, StreamEvent } from '@/api/types'
import {
  buildConnections,
  bySite,
  clientName,
  connectionKey,
  explain,
  leadAlert,
  matchesSite,
} from './stream-data'

const chromium: ClientRead = {
  known_as: null,
  family: 'chromium',
  family_name: 'Chromium family',
  confidence: 'high',
  reasons: ['ALPS'],
  caveat: null,
}

let seq = 0
function hello(
  src: string,
  dst: string,
  sni: string | undefined,
  ja4: string,
  client: ClientRead | undefined = chromium
): LiveItem {
  seq += 1
  return {
    seq,
    animate: false,
    message: {
      type: 'flow',
      client,
      event: {
        kind: 'client_hello',
        ts_nanos: seq * 1_000,
        src,
        dst,
        ja3: 'a',
        ja3_raw: 'a',
        ja4: { hash: ja4, raw: 'raw' },
        sni,
        alpn: 'h2',
      },
    },
  }
}

function serverHello(src: string, dst: string): LiveItem {
  seq += 1
  return {
    seq,
    animate: false,
    message: {
      type: 'flow',
      event: {
        kind: 'server_hello',
        ts_nanos: seq * 1_000,
        src,
        dst,
        ja3s: 'b',
        ja3s_raw: 'b',
        ja4s: { hash: 't130200_1301_x', raw: 'r' },
      },
    },
  }
}

describe('connectionKey', () => {
  it('gives both directions of one connection the same key', () => {
    const c = hello('10.0.0.5:50000', '1.2.3.4:443', 'a.com', 't13d')
    const s = serverHello('1.2.3.4:443', '10.0.0.5:50000')
    const ck = (i: LiveItem): string =>
      connectionKey((i.message as { event: StreamEvent }).event)
    expect(ck(c)).toBe(ck(s))
  })
})

describe('buildConnections', () => {
  it('attaches the server name and client of the hello to the server reply', () => {
    const feed = [
      serverHello('1.2.3.4:443', '10.0.0.5:50000'),
      hello('10.0.0.5:50000', '1.2.3.4:443', 'a.com', 't13d1516h2_x_y'),
    ]
    const conns = [...buildConnections(feed).values()]
    expect(conns).toHaveLength(1)
    expect(conns[0].sni).toBe('a.com')
    expect(conns[0].client?.family).toBe('chromium')
    expect(conns[0].transport).toBe('tcp')
    expect(conns[0].items).toHaveLength(2)
  })

  it('marks QUIC by the JA4 transport letter', () => {
    const conns = [
      ...buildConnections([
        hello('10.0.0.5:1', '1.2.3.4:443', 'q.com', 'q13d0310h3_x_y'),
      ]).values(),
    ]
    expect(conns[0].transport).toBe('quic')
  })
})

describe('clientName', () => {
  it('prefers an exact feed match over the shape guess', () => {
    expect(clientName({ ...chromium, known_as: 'Google Chrome 120' })).toEqual({
      text: 'Google Chrome 120',
      basis: 'exact',
    })
    expect(clientName(chromium)).toEqual({ text: 'Chromium', basis: 'inferred' })
    expect(clientName({ ...chromium, family: 'unknown' }).basis).toBe('none')
    expect(clientName(undefined).text).toBe('')
  })
})

describe('bySite', () => {
  const feed = [
    hello('10.0.0.5:3', '1.2.3.4:443', 'a.com', 't13d_one'),
    hello('10.0.0.5:2', '1.2.3.4:443', 'a.com', 't13d_one'),
    hello('10.0.0.5:1', '5.6.7.8:443', 'b.com', 'q13d_two'),
    hello('10.0.0.5:9', '5.6.7.8:443', undefined, 't13d_one'),
  ]

  it('groups by server name with the clients that reached it', () => {
    const rows = bySite(feed)
    expect(rows[0].site).toBe('a.com')
    expect(rows[0].connections).toBe(2)
    expect(rows[0].clients).toHaveLength(1)
    const b = rows.find((r) => r.site === 'b.com')
    expect(b?.quic).toBe(1)
    expect(rows.some((r) => r.site === '(no server name)')).toBe(true)
  })

  it('filters by site, fingerprint or client name', () => {
    const rows = bySite(feed)
    expect(rows.filter((r) => matchesSite(r, 'b.co'))).toHaveLength(1)
    expect(rows.filter((r) => matchesSite(r, 'q13d'))).toHaveLength(1)
    expect(rows.filter((r) => matchesSite(r, 'chromium'))).toHaveLength(3)
  })
})

describe('explain', () => {
  it('names the site and the client in plain words', () => {
    const c = hello('10.0.0.5:50000', '1.2.3.4:443', 'a.com', 't13d1516h2_x_y')
    const conn = [...buildConnections([c]).values()][0]
    const event = (c.message as { event: StreamEvent }).event
    const text = explain(event, conn)
    expect(text).toContain('a.com')
    expect(text).toContain('Chromium')
    expect(text).toContain('inferred')
  })
})

describe('leadAlert', () => {
  it('picks the most severe alert', () => {
    const base = {
      ts_nanos: 1,
      rule: 'first_seen' as const,
      title: 't',
      detail: 'd',
    }
    const lead = leadAlert([
      { ...base, severity: 'info' },
      { ...base, severity: 'high', rule: 'known_bad' },
    ])
    expect(lead?.rule).toBe('known_bad')
    expect(leadAlert([])).toBeUndefined()
  })
})
