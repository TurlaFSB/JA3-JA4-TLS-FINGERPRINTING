/**
 * © Pranav Verma | 2026
 * dns-data.ts
 */

import type { DnsName, DnsView } from '@/api/types'

export interface DnsFilter {
  query: string
  randomOnly: boolean
  failingOnly: boolean
}

export function matchesName(name: DnsName, filter: DnsFilter): boolean {
  if (filter.randomOnly && !name.random_looking) return false
  if (filter.failingOnly && name.nxdomain + name.failures === 0) return false
  const needle = filter.query.trim().toLowerCase()
  if (needle === '') return true
  return `${name.name} ${name.addresses.join(' ')}`.toLowerCase().includes(needle)
}

// The share of answered lookups that came back "no such name". Zero when
// nothing has been answered, rather than a division by nothing.
export function failureRate(totals: DnsView['totals']): number {
  return totals.responses === 0 ? 0 : totals.nxdomain / totals.responses
}

export function percent(share: number): string {
  if (share === 0) return '0%'
  return `${(share * 100).toFixed(share < 0.1 ? 1 : 0)}%`
}

export function result(rcode: string, answers: string[]): string {
  if (rcode === '') return 'asked'
  if (rcode !== 'NOERROR') return rcode.toLowerCase()
  return answers.length > 0 ? answers.join(', ') : 'no address'
}
