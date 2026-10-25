/**
 * © Pranav Verma | 2026
 * dns-data.ts
 */

import type { DnsLookup, DnsName, DnsView, TrafficFlow } from '@/api/types'
import { splitAddr } from '@/api/types'

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
  return `${name.name} ${name.reverse_of ?? ''} ${name.addresses.join(' ')}`
    .toLowerCase()
    .includes(needle)
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

// What each record type asks for, in words.
export const QTYPE_WORDS: Record<string, string> = {
  A: 'IPv4 address',
  AAAA: 'IPv6 address',
  PTR: 'name of an address (reverse lookup)',
  CNAME: 'alias',
  MX: 'mail server',
  TXT: 'text record',
  NS: 'name server',
  SRV: 'service location',
  SOA: 'zone authority',
  HTTPS: 'web service hints',
  SVCB: 'service hints',
  ANY: 'everything',
}

export function qtypeWords(qtype: string): string {
  return QTYPE_WORDS[qtype] ?? qtype
}

const RCODE_WORDS: Record<string, string> = {
  NOERROR: 'answered',
  NXDOMAIN: 'no such name',
  SERVFAIL: 'the server failed',
  REFUSED: 'refused',
  FORMERR: 'malformed query',
  NOTIMP: 'not supported',
}

// What a lookup came to, in words.
export function resultWords(lookup: DnsLookup): string {
  if (lookup.rcode === '') return 'asked, no answer seen'
  if (lookup.rcode !== 'NOERROR') {
    return RCODE_WORDS[lookup.rcode] ?? lookup.rcode.toLowerCase()
  }
  const data = lookup.answers.filter((a) => a.data !== '').map((a) => a.data)
  if (data.some((d) => d === '0.0.0.0' || d === '::')) {
    return 'blocked (answered with an empty address)'
  }
  return data.length > 0 ? data.join(', ') : 'answered, no address'
}

export function isFailure(lookup: DnsLookup): boolean {
  return lookup.rcode !== '' && lookup.rcode !== 'NOERROR'
}

// The name to show: a reverse lookup is shown as the address it asks about.
export function displayName(row: {
  name: string
  reverse_of: string | null
}): string {
  return row.reverse_of ?? row.name
}

export const KIND_WORDS: Record<DnsName['kind'], string> = {
  internet: 'internet name',
  local: 'local name',
  reverse: 'reverse lookup',
}

// One plain sentence about what a name is and what happened to it.
export function meaning(row: DnsName): string {
  const asked = `${row.queries} time${row.queries === 1 ? '' : 's'} by ${row.clients} host${row.clients === 1 ? '' : 's'}`
  if (row.kind === 'reverse') {
    const who = row.reverse_of ?? row.name
    const answer = row.addresses[0]
    return answer
      ? `A reverse lookup: something asked which name belongs to ${who}, and the DNS server said ${answer}. Asked ${asked}.`
      : `A reverse lookup: something asked which name belongs to ${who}. ${row.nxdomain > 0 ? 'The DNS server said it has none.' : 'No name was returned.'} Asked ${asked}. Operating systems and tools do this to turn an address into a readable name.`
  }
  if (row.blocked) {
    return `Asked ${asked}. The DNS server answered with an empty address (0.0.0.0), the way an ad or tracker blocklist does: the name is deliberately blocked.`
  }
  if (row.nxdomain > 0 && row.answered === row.nxdomain) {
    return row.kind === 'local'
      ? `Asked ${asked}, and the DNS server said it does not exist. This looks like an internal name that this DNS server does not know: a program or setting points at a host that cannot be found.`
      : `Asked ${asked}, and the DNS server said it does not exist (NXDOMAIN). A typo, a retired service, or software probing for names looks like this.`
  }
  if (row.nxdomain > 0) {
    return `Asked ${asked}. Some lookups resolved and ${row.nxdomain} said "no such name".`
  }
  if (row.addresses.length > 0) {
    return `Asked ${asked}; it resolved to ${row.addresses.join(', ')}.`
  }
  return `Asked ${asked}. No answer has been seen yet.`
}

// The conversations that followed a name: those whose server address it
// resolved to, or whose handshake named it.
export function flowsFor(row: DnsName, flows: TrafficFlow[]): TrafficFlow[] {
  const addresses = new Set(row.addresses)
  return flows.filter(
    (flow) =>
      flow.sni === row.name ||
      flow.dns_name === row.name ||
      addresses.has(splitAddr(flow.server).host)
  )
}

export function lookupsFor(name: string, recent: DnsLookup[]): DnsLookup[] {
  return mergeLookups(recent).filter((lookup) => lookup.name === name)
}

// "What is happening", from the numbers: a few sentences a person can act on.
export function summarize(view: DnsView, hostname: string | null): string[] {
  const { totals } = view
  if (totals.queries + totals.responses === 0) return []
  const lines: string[] = []
  const hosts = view.top_clients.length
  const servers = view.resolvers.map((r) => r.resolver)
  lines.push(
    `${totals.queries.toLocaleString()} DNS question${totals.queries === 1 ? '' : 's'} from ${hosts} host${hosts === 1 ? '' : 's'}${hostname ? ` (this computer is ${hostname})` : ''}, asked of ${servers.length > 0 ? servers.join(', ') : 'an unseen server'}.`
  )
  const top = view.top_names.find((n) => n.kind !== 'reverse')
  if (top) {
    lines.push(`The most asked name is ${top.name} (${top.queries}×).`)
  }
  const reverse = view.top_names.filter((n) => n.kind === 'reverse').length
  if (reverse > 0) {
    lines.push(
      `${reverse} reverse lookup${reverse === 1 ? '' : 's'}: tools turning addresses back into names.`
    )
  }
  if (totals.nxdomain > 0) {
    const worst = view.top_failing[0]
    lines.push(
      `${totals.nxdomain} lookup${totals.nxdomain === 1 ? '' : 's'} came back "no such name" (${percent(failureRate(totals))} of answers)${worst ? `, most often ${displayName(worst)}` : ''}.`
    )
  }
  if (totals.failures > 0) {
    lines.push(
      `${totals.failures} answer${totals.failures === 1 ? '' : 's'} were server failures: the DNS server could not answer.`
    )
  }
  const slow = view.resolvers.find((r) => (r.latency_ms ?? 0) > 200)
  if (slow) {
    lines.push(
      `${slow.resolver} is slow to answer (about ${Math.round(slow.latency_ms ?? 0)} ms).`
    )
  }
  return lines
}

export function latencyText(ms: number | null): string {
  if (ms === null) return ''
  return ms < 1 ? '<1 ms' : `${Math.round(ms)} ms`
}

export const NAME_HEADERS = [
  'name',
  'kind',
  'reverse_of',
  'asked',
  'hosts',
  'nxdomain',
  'failures',
  'types',
  'asked_of',
  'answers',
  'avg_answer_ms',
  'random_looking',
  'blocked',
]

// The names as spreadsheet rows.
export function nameRows(
  names: DnsName[]
): (string | number | boolean | null)[][] {
  return names.map((n) => [
    n.name,
    n.kind,
    n.reverse_of,
    n.queries,
    n.clients,
    n.nxdomain,
    n.failures,
    n.qtypes.join(' '),
    n.resolvers.join(' '),
    n.addresses.join(' '),
    n.latency_ms === null ? '' : Math.round(n.latency_ms),
    n.random_looking,
    n.blocked,
  ])
}

// The lookups as people think of them: one line per question. A query whose
// answer is also in the list is dropped in favour of the answer, which carries
// the result and the time it took. Queries still waiting for an answer stay.
// The list is newest first.
export function mergeLookups(recent: DnsLookup[]): DnsLookup[] {
  const answered = new Map<string, number>()
  for (const lookup of recent) {
    if (lookup.rcode === '') continue
    const key = `${lookup.client}|${lookup.name}|${lookup.qtype}`
    answered.set(key, Math.max(answered.get(key) ?? 0, lookup.ts_nanos))
  }
  return recent.filter((lookup) => {
    if (lookup.rcode !== '') return true
    const key = `${lookup.client}|${lookup.name}|${lookup.qtype}`
    return (answered.get(key) ?? 0) < lookup.ts_nanos
  })
}
