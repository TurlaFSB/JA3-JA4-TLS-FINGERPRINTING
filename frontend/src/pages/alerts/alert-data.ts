/**
 * © Pranav Verma | 2026
 * alert-data.ts
 */

import type { Alert, Rule, Severity } from '@/api/types'

export const SEVERITIES: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
]

export const RULE_NOTES: Record<Rule, { what: string; next: string }> = {
  known_bad: {
    what: 'A fingerprint matched malicious or suspicious intelligence. Raised once per source address.',
    next: 'Confirm the host. A match names a client family, not proof of compromise: a shared library produces the same fingerprint.',
  },
  ua_mismatch: {
    what: 'A request claimed a browser User-Agent while the same client’s TLS fingerprint belongs to a script or tool.',
    next: 'Look at the process behind the address. Scripts that copy a browser User-Agent are common; so is malware doing it.',
  },
  os_mismatch: {
    what: 'The operating system implied by the User-Agent disagrees with the one implied by the TCP SYN fingerprint.',
    next: 'Check for a proxy, VPN or mobile tethering in the path, which also cause this.',
  },
  first_seen: {
    what: 'This fingerprint has never been recorded before. Informational.',
    next: 'Expected on a fresh database. A new fingerprint on a quiet host is worth a look.',
  },
  fp_rotation: {
    what: 'One address presented many distinct fingerprints inside the window.',
    next: 'Several programs behind one address (NAT, proxy) look the same. Declare it with --shared-network to silence that case.',
  },
  monoculture: {
    what: 'One fingerprint appeared from many distinct addresses inside the window.',
    next: 'Common for popular software. A rare fingerprint across many hosts suggests one tool deployed widely.',
  },
  header_anomaly: {
    what: 'A cleartext request claiming a browser carried headers browsers never send to that origin.',
    next: 'Typical of impersonation tools left on defaults. Trivially avoided by a careful attacker.',
  },
}

export interface AlertFilter {
  severities: Set<Severity>
  rules: Set<Rule>
  query: string
}

export function matchesFilter(alert: Alert, filter: AlertFilter): boolean {
  if (filter.severities.size > 0 && !filter.severities.has(alert.severity)) {
    return false
  }
  if (filter.rules.size > 0 && !filter.rules.has(alert.rule)) return false
  const needle = filter.query.trim().toLowerCase()
  if (needle === '') return true
  const haystack =
    `${alert.title} ${alert.detail} ${alert.ip ?? ''} ${alert.fp_value ?? ''} ${alert.rule}`.toLowerCase()
  return haystack.includes(needle)
}

export function countBy<K extends string>(
  alerts: Alert[],
  key: (alert: Alert) => K
): Map<K, number> {
  const counts = new Map<K, number>()
  for (const alert of alerts) {
    const k = key(alert)
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  return counts
}

export function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}
