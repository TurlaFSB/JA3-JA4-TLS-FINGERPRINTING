// ===================
// © Pranav Verma | 2026
// dns.types.ts
// ===================

import { z } from 'zod'

export const dnsNameSchema = z.object({
  name: z.string(),
  queries: z.number(),
  answered: z.number(),
  nxdomain: z.number(),
  failures: z.number(),
  clients: z.number(),
  last_ts: z.number(),
  addresses: z.array(z.string()),
  random_looking: z.boolean(),
})

export const dnsViewSchema = z.object({
  totals: z.object({
    queries: z.number(),
    responses: z.number(),
    nxdomain: z.number(),
    failures: z.number(),
  }),
  top_names: z.array(dnsNameSchema),
  top_failing: z.array(dnsNameSchema),
  top_clients: z.array(
    z.object({ client: z.string(), queries: z.number(), nxdomain: z.number() })
  ),
  recent: z.array(
    z.object({
      ts_nanos: z.number(),
      client: z.string(),
      resolver: z.string(),
      name: z.string(),
      qtype: z.string(),
      rcode: z.string(),
      answers: z.array(z.string()),
    })
  ),
})

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
