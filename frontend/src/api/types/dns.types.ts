// ===================
// © Pranav Verma | 2026
// dns.types.ts
// ===================

import { z } from 'zod'

export const dnsAnswerSchema = z.object({
  rtype: z.string(),
  data: z.string(),
  ttl: z.number(),
})

export const dnsNameSchema = z.object({
  name: z.string(),
  kind: z.enum(['internet', 'local', 'reverse']),
  reverse_of: z.string().nullable(),
  queries: z.number(),
  answered: z.number(),
  nxdomain: z.number(),
  failures: z.number(),
  clients: z.number(),
  first_ts: z.number(),
  last_ts: z.number(),
  qtypes: z.array(z.string()),
  resolvers: z.array(z.string()),
  addresses: z.array(z.string()),
  latency_ms: z.number().nullable(),
  ttl: z.number().nullable(),
  blocked: z.boolean(),
  random_looking: z.boolean(),
})

export const dnsLookupSchema = z.object({
  ts_nanos: z.number(),
  client: z.string(),
  resolver: z.string(),
  name: z.string(),
  qtype: z.string(),
  rcode: z.string(),
  answers: z.array(dnsAnswerSchema),
  reverse_of: z.string().nullable(),
  latency_ms: z.number().nullable(),
})

export const dnsViewSchema = z.object({
  totals: z.object({
    queries: z.number(),
    responses: z.number(),
    nxdomain: z.number(),
    failures: z.number(),
    since_ts: z.number(),
    last_ts: z.number(),
  }),
  top_names: z.array(dnsNameSchema),
  top_failing: z.array(dnsNameSchema),
  top_clients: z.array(
    z.object({
      client: z.string(),
      queries: z.number(),
      nxdomain: z.number(),
      resolvers: z.array(z.string()),
    })
  ),
  resolvers: z.array(
    z.object({
      resolver: z.string(),
      queries: z.number(),
      nxdomain: z.number(),
      latency_ms: z.number().nullable(),
      clients: z.number(),
    })
  ),
  recent: z.array(dnsLookupSchema),
})

export type DnsLookup = z.infer<typeof dnsLookupSchema>
export type DnsView = z.infer<typeof dnsViewSchema>
export type DnsName = z.infer<typeof dnsNameSchema>

export const interfaceSchema = z.object({
  name: z.string(),
  description: z.string().nullable(),
  up: z.boolean(),
  kind: z.enum(['physical', 'virtual', 'loopback', 'pseudo']),
  addresses: z.array(z.string()),
  auto: z.boolean(),
})

export const interfacesViewSchema = z.object({
  available: z.boolean(),
  reason: z.string().nullable(),
  current: z.string().nullable(),
  interfaces: z.array(interfaceSchema),
})

export type InterfacesView = z.infer<typeof interfacesViewSchema>
