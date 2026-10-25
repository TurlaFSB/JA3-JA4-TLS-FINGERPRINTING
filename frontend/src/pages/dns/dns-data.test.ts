/**
 * © Pranav Verma | 2026
 * dns-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { DnsLookup, DnsName, DnsView } from '@/api/types'
import {
  displayName,
  failureRate,
  latencyText,
  matchesName,
  meaning,
  mergeLookups,
  percent,
  resultWords,
  summarize,
} from './dns-data'

const name = (over: Partial<DnsName>): DnsName => ({
  name: 'www.example.com',
  kind: 'internet',
  reverse_of: null,
  queries: 4,
  answered: 4,
  nxdomain: 0,
  failures: 0,
  clients: 1,
  first_ts: 0,
  last_ts: 0,
  qtypes: ['A'],
  resolvers: ['10.0.0.1'],
  addresses: ['93.184.216.34'],
  latency_ms: 12,
  ttl: 60,
  blocked: false,
  random_looking: false,
  ...over,
})

const lookup = (over: Partial<DnsLookup>): DnsLookup => ({
  ts_nanos: 0,
  client: '10.0.0.5',
  resolver: '10.0.0.1',
  name: 'www.example.com',
  qtype: 'A',
  rcode: 'NOERROR',
  answers: [],
  reverse_of: null,
  latency_ms: null,
  ...over,
})

describe('matchesName', () => {
  const none = { query: '', randomOnly: false, failingOnly: false }

  it('matches on the name, the address it asks about, or an answer', () => {
    expect(matchesName(name({}), { ...none, query: 'EXAMPLE' })).toBe(true)
    expect(matchesName(name({}), { ...none, query: '93.184' })).toBe(true)
    expect(
      matchesName(name({ reverse_of: '10.1.1.1' }), {
        ...none,
        query: '10.1.1.1',
      })
    ).toBe(true)
    expect(matchesName(name({}), { ...none, query: 'other' })).toBe(false)
  })

  it('narrows to random-looking and to failing names', () => {
    expect(matchesName(name({}), { ...none, randomOnly: true })).toBe(false)
    expect(
      matchesName(name({ random_looking: true }), { ...none, randomOnly: true })
    ).toBe(true)
    expect(matchesName(name({}), { ...none, failingOnly: true })).toBe(false)
    expect(
      matchesName(name({ nxdomain: 1 }), { ...none, failingOnly: true })
    ).toBe(true)
  })
})

describe('words', () => {
  const totals = {
    queries: 0,
    responses: 0,
    nxdomain: 0,
    failures: 0,
    since_ts: 0,
    last_ts: 0,
  }

  it('does not divide by nothing', () => {
    expect(failureRate(totals)).toBe(0)
    expect(failureRate({ ...totals, responses: 10, nxdomain: 2 })).toBeCloseTo(
      0.2
    )
  })

  it('formats shares, times and results', () => {
    expect(percent(0)).toBe('0%')
    expect(percent(0.034)).toBe('3.4%')
    expect(percent(0.5)).toBe('50%')
    expect(latencyText(null)).toBe('')
    expect(latencyText(0.4)).toBe('<1 ms')
    expect(latencyText(12.6)).toBe('13 ms')
    expect(resultWords(lookup({ rcode: '' }))).toBe('asked, no answer seen')
    expect(resultWords(lookup({ rcode: 'NXDOMAIN' }))).toBe('no such name')
    expect(
      resultWords(lookup({ answers: [{ rtype: 'A', data: '1.2.3.4', ttl: 1 }] }))
    ).toBe('1.2.3.4')
    expect(
      resultWords(lookup({ answers: [{ rtype: 'A', data: '0.0.0.0', ttl: 1 }] }))
    ).toContain('blocked')
  })

  it('shows a reverse lookup as the address it asks about', () => {
    expect(
      displayName({ name: '1.0.0.10.in-addr.arpa', reverse_of: '10.0.0.1' })
    ).toBe('10.0.0.1')
    expect(displayName({ name: 'a.example', reverse_of: null })).toBe('a.example')
  })

  it('explains a name that does not exist, a blocked one and a reverse lookup', () => {
    expect(
      meaning(
        name({
          kind: 'local',
          nxdomain: 3,
          answered: 3,
          queries: 3,
          addresses: [],
        })
      )
    ).toContain('internal name')
    expect(
      meaning(name({ kind: 'internet', nxdomain: 2, answered: 2, addresses: [] }))
    ).toContain('NXDOMAIN')
    expect(meaning(name({ blocked: true, addresses: ['0.0.0.0'] }))).toContain(
      'blocklist'
    )
    expect(
      meaning(name({ kind: 'reverse', reverse_of: '10.0.0.1', addresses: [] }))
    ).toContain('which name belongs to 10.0.0.1')
  })
})

describe('summarize', () => {
  const view: DnsView = {
    totals: {
      queries: 11,
      responses: 10,
      nxdomain: 6,
      failures: 0,
      since_ts: 0,
      last_ts: 0,
    },
    top_names: [name({ name: 'wazuh.indexer', kind: 'local' })],
    top_failing: [name({ name: 'wazuh.indexer', nxdomain: 3 })],
    top_clients: [
      { client: '10.0.0.5', queries: 9, nxdomain: 5, resolvers: ['10.0.0.1'] },
    ],
    resolvers: [
      {
        resolver: '10.0.0.1',
        queries: 11,
        nxdomain: 6,
        latency_ms: 4,
        clients: 1,
      },
    ],
    recent: [],
  }

  it('says nothing when nothing was heard', () => {
    expect(
      summarize(
        { ...view, totals: { ...view.totals, queries: 0, responses: 0 } },
        null
      )
    ).toEqual([])
  })

  it('names the asker, the server, the busiest name and the failures', () => {
    const text = summarize(view, 'my-laptop').join(' ')
    expect(text).toContain('11 DNS questions from 1 host')
    expect(text).toContain('this computer is my-laptop')
    expect(text).toContain('10.0.0.1')
    expect(text).toContain('wazuh.indexer')
    expect(text).toContain('"no such name"')
  })
})

describe('mergeLookups', () => {
  it('keeps the answer and drops the query it answers', () => {
    const merged = mergeLookups([
      lookup({ ts_nanos: 30, rcode: 'NOERROR' }),
      lookup({ ts_nanos: 20, rcode: '' }),
      lookup({ ts_nanos: 10, rcode: '', name: 'other.example' }),
    ])
    expect(merged.map((l) => `${l.name}:${l.rcode || 'asked'}`)).toEqual([
      'www.example.com:NOERROR',
      'other.example:asked',
    ])
  })

  it('keeps a query asked again after the last answer', () => {
    const merged = mergeLookups([
      lookup({ ts_nanos: 50, rcode: '' }),
      lookup({ ts_nanos: 30, rcode: 'NOERROR' }),
    ])
    expect(merged).toHaveLength(2)
  })
})
