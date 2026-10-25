/**
 * © Pranav Verma | 2026
 * traffic-data.test.ts
 */

import { describe, expect, it } from 'vitest'
import type { TrafficFlow } from '@/api/types'
import {
  chartMax,
  FLOW_HEADERS,
  type FlowFilter,
  flowRows,
  linePath,
  matchesFlow,
  sortFlows,
} from './traffic-data'

const flow = (over: Partial<TrafficFlow>): TrafficFlow => ({
  proto: 'tcp',
  client: '192.168.1.5:50000',
  server: '93.184.216.34:443',
  direction: 'outbound',
  service: 'https',
  state: 'open',
  first_ns: 0,
  last_ns: 10,
  bytes_up: 100,
  bytes_down: 900,
  packets_up: 2,
  packets_down: 3,
  sni: 'example.com',
  dns_name: null,
  alpn: 'h2',
  ja4: 't13d1516h2_x',
  client_info: { known_as: 'Firefox 158', family: 'firefox' },
  ...over,
})

const all: FlowFilter = {
  direction: 'all',
  proto: 'all',
  namedOnly: false,
  query: '',
}

describe('matchesFlow', () => {
  it('filters by direction, protocol and whether a name was seen', () => {
    expect(matchesFlow(flow({}), all)).toBe(true)
    expect(matchesFlow(flow({}), { ...all, direction: 'inbound' })).toBe(false)
    expect(matchesFlow(flow({ proto: 'udp' }), { ...all, proto: 'tcp' })).toBe(
      false
    )
    expect(matchesFlow(flow({ sni: null }), { ...all, namedOnly: true })).toBe(
      false
    )
  })

  it('searches addresses, names, services and the identified client', () => {
    expect(matchesFlow(flow({}), { ...all, query: 'EXAMPLE' })).toBe(true)
    expect(matchesFlow(flow({}), { ...all, query: 'firefox 158' })).toBe(true)
    expect(matchesFlow(flow({}), { ...all, query: '192.168.1.5' })).toBe(true)
    expect(matchesFlow(flow({}), { ...all, query: 'smtp' })).toBe(false)
  })
})

describe('sortFlows', () => {
  const a = flow({ client: 'a', last_ns: 5, bytes_down: 10, first_ns: 4 })
  const b = flow({ client: 'b', last_ns: 9, bytes_down: 5000, first_ns: 8 })
  const c = flow({ client: 'c', last_ns: 7, bytes_down: 100, first_ns: 0 })

  it('orders by recency, size or duration without mutating the input', () => {
    const input = [a, b, c]
    expect(sortFlows(input, 'recent').map((f) => f.client)).toEqual([
      'b',
      'c',
      'a',
    ])
    expect(sortFlows(input, 'bytes').map((f) => f.client)).toEqual([
      'b',
      'c',
      'a',
    ])
    expect(sortFlows(input, 'duration').map((f) => f.client)).toEqual([
      'c',
      'a',
      'b',
    ])
    expect(input.map((f) => f.client)).toEqual(['a', 'b', 'c'])
  })
})

describe('chart helpers', () => {
  it('rounds the scale up to a readable step', () => {
    expect(chartMax([0, 0])).toBe(1)
    expect(chartMax([120, 3400])).toBe(4000)
    expect(chartMax([9, 1])).toBe(9)
  })

  it('draws one point per sample and nothing for none', () => {
    expect(linePath([], 100, 10, 1)).toBe('')
    expect(linePath([0, 5, 10], 100, 10, 10)).toBe(
      'M0.0 10.0 L50.0 5.0 L100.0 0.0'
    )
    expect(linePath([4], 100, 10, 10)).toBe('M0.0 6.0')
  })
})

describe('flowRows', () => {
  it('says where a server name came from', () => {
    const rows = flowRows([
      flow({}),
      flow({ sni: null, dns_name: 'cdn.example' }),
      flow({ sni: null, dns_name: null }),
    ])
    for (const row of rows) expect(row).toHaveLength(FLOW_HEADERS.length)
    const source = FLOW_HEADERS.indexOf('name_source')
    expect(rows.map((r) => r[source])).toEqual(['handshake', 'dns', ''])
  })
})
