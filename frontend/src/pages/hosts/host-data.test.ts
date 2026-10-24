/**
 * © Pranav Verma | 2026
 * host-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { ClientSpan, HostSummary } from '@/api/types'
import {
  appeared,
  barFor,
  laterClients,
  matchesHost,
  sortHosts,
} from './host-data'

const client = (first: number, last: number, ja4 = 'x'): ClientSpan => ({
  ja4,
  label: null,
  verdict: null,
  first_ts: first,
  last_ts: last,
  count: 1,
  servers: [],
})

const host = (
  ip: string,
  last: number,
  clients: number,
  alerts: number
): HostSummary => ({
  ip,
  first_ts: 0,
  last_ts: last,
  observations: 1,
  clients,
  servers: 0,
  alerts,
  verdict: null,
  top_label: ip === '10.0.0.1' ? 'Firefox 158' : null,
})

describe('barFor', () => {
  it('places a client on the host timeline', () => {
    const bar = barFor(client(25, 75), 0, 100)
    expect(bar.left).toBe(25)
    expect(bar.width).toBe(50)
  })

  it('keeps an instant visible and inside the track', () => {
    const bar = barFor(client(100, 100), 0, 100)
    expect(bar.width).toBeGreaterThan(0)
    expect(bar.left + bar.width).toBeLessThanOrEqual(100)
  })

  it('fills the track when the host was seen at one instant', () => {
    expect(barFor(client(5, 5), 5, 5)).toEqual({ left: 0, width: 100 })
  })
})

describe('change helpers', () => {
  it('lists the clients that appeared after the first', () => {
    const later = laterClients([
      client(50, 60, 'b'),
      client(0, 10, 'a'),
      client(80, 90, 'c'),
    ])
    expect(later.map((c) => c.ja4)).toEqual(['b', 'c'])
  })

  it('says how long after the first sighting a client appeared', () => {
    expect(appeared(client(0, 1), 0)).toBe('with the first sighting')
    expect(appeared(client(3_000_000_000, 4), 0)).toBe(
      '3.0 s after the first sighting'
    )
  })
})

describe('host list', () => {
  const hosts = [
    host('10.0.0.1', 5, 1, 0),
    host('10.0.0.2', 9, 3, 2),
    host('10.0.0.3', 7, 3, 5),
  ]

  it('sorts without mutating', () => {
    expect(sortHosts(hosts, 'recent').map((h) => h.ip)).toEqual([
      '10.0.0.2',
      '10.0.0.3',
      '10.0.0.1',
    ])
    expect(sortHosts(hosts, 'clients').map((h) => h.ip)).toEqual([
      '10.0.0.2',
      '10.0.0.3',
      '10.0.0.1',
    ])
    expect(sortHosts(hosts, 'alerts').map((h) => h.ip)).toEqual([
      '10.0.0.3',
      '10.0.0.2',
      '10.0.0.1',
    ])
    expect(hosts[0].ip).toBe('10.0.0.1')
  })

  it('filters by address or label', () => {
    expect(matchesHost(hosts[0], 'firefox')).toBe(true)
    expect(matchesHost(hosts[1], '10.0.0.2')).toBe(true)
    expect(matchesHost(hosts[1], 'firefox')).toBe(false)
  })
})
