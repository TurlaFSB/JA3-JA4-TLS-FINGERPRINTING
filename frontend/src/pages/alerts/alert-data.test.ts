/**
 * © Pranav Verma | 2026
 * alert-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { Alert } from '@/api/types'
import { type AlertFilter, countBy, matchesFilter, toggle } from './alert-data'

const alert = (over: Partial<Alert>): Alert => ({
  ts_nanos: 1,
  rule: 'first_seen',
  severity: 'info',
  title: 'first time this ja4 fingerprint has been seen',
  detail: 'recorded',
  ...over,
})

const none: AlertFilter = {
  severities: new Set(),
  rules: new Set(),
  query: '',
}

describe('matchesFilter', () => {
  it('passes everything when nothing is selected', () => {
    expect(matchesFilter(alert({}), none)).toBe(true)
  })

  it('filters by severity and rule together', () => {
    const a = alert({ rule: 'known_bad', severity: 'high' })
    expect(matchesFilter(a, { ...none, severities: new Set(['high']) })).toBe(
      true
    )
    expect(matchesFilter(a, { ...none, severities: new Set(['low']) })).toBe(
      false
    )
    expect(matchesFilter(a, { ...none, rules: new Set(['first_seen']) })).toBe(
      false
    )
  })

  it('searches title, detail, address and fingerprint', () => {
    const a = alert({ ip: '10.0.0.9', fp_value: 't13d1516h2_abc' })
    expect(matchesFilter(a, { ...none, query: '10.0.0.9' })).toBe(true)
    expect(matchesFilter(a, { ...none, query: 'T13D1516' })).toBe(true)
    expect(matchesFilter(a, { ...none, query: 'nope' })).toBe(false)
  })
})

describe('helpers', () => {
  it('counts alerts per key', () => {
    const counts = countBy(
      [alert({}), alert({ severity: 'high' }), alert({})],
      (x) => x.severity
    )
    expect(counts.get('info')).toBe(2)
    expect(counts.get('high')).toBe(1)
  })

  it('toggles set membership without mutating', () => {
    const base = new Set(['a'])
    expect(toggle(base, 'b').has('b')).toBe(true)
    expect(toggle(base, 'a').has('a')).toBe(false)
    expect(base.has('a')).toBe(true)
  })
})
