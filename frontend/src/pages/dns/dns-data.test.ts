/**
 * © Pranav Verma | 2026
 * dns-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { DnsName } from '@/api/types'
import { failureRate, matchesName, percent, result } from './dns-data'

const name = (over: Partial<DnsName>): DnsName => ({
  name: 'www.example.com',
  queries: 4,
  answered: 4,
  nxdomain: 0,
  failures: 0,
  clients: 1,
  last_ts: 0,
  addresses: ['93.184.216.34'],
  random_looking: false,
  ...over,
})

describe('matchesName', () => {
  const none = { query: '', randomOnly: false, failingOnly: false }

  it('matches on the name or an address it resolved to', () => {
    expect(matchesName(name({}), { ...none, query: 'EXAMPLE' })).toBe(true)
    expect(matchesName(name({}), { ...none, query: '93.184' })).toBe(true)
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

describe('summaries', () => {
  it('does not divide by nothing', () => {
    expect(
      failureRate({ queries: 0, responses: 0, nxdomain: 0, failures: 0 })
    ).toBe(0)
    expect(
      failureRate({ queries: 10, responses: 10, nxdomain: 2, failures: 0 })
    ).toBeCloseTo(0.2)
  })

  it('formats shares and results', () => {
    expect(percent(0)).toBe('0%')
    expect(percent(0.034)).toBe('3.4%')
    expect(percent(0.5)).toBe('50%')
    expect(result('', [])).toBe('asked')
    expect(result('NXDOMAIN', [])).toBe('nxdomain')
    expect(result('NOERROR', ['1.2.3.4', '5.6.7.8'])).toBe('1.2.3.4, 5.6.7.8')
    expect(result('NOERROR', [])).toBe('no address')
  })
})
