// ===================
// © Pranav Verma | 2026
// traffic.types.ts
// ===================

import { z } from 'zod'

export const totalsSchema = z.object({
  out_bytes: z.number(),
  out_packets: z.number(),
  in_bytes: z.number(),
  in_packets: z.number(),
  internal_bytes: z.number(),
  internal_packets: z.number(),
  transit_bytes: z.number(),
  transit_packets: z.number(),
  flows_shed: z.number(),
})

export const trafficFlowSchema = z.object({
  proto: z.enum(['tcp', 'udp']),
  client: z.string(),
  server: z.string(),
  direction: z.enum(['outbound', 'inbound', 'internal', 'transit']),
  service: z.string().nullable(),
  state: z.enum(['open', 'closed', 'reset']),
  first_ns: z.number(),
  last_ns: z.number(),
  bytes_up: z.number(),
  bytes_down: z.number(),
  packets_up: z.number(),
  packets_down: z.number(),
  sni: z.string().nullable(),
  alpn: z.string().nullable(),
  ja4: z.string().nullable(),
  client_info: z
    .object({ known_as: z.string().nullable(), family: z.string() })
    .nullable(),
})

export const talkerSchema = z.object({
  host: z.string(),
  flows: z.number(),
  bytes_up: z.number(),
  bytes_down: z.number(),
  names: z.array(z.string()),
})

export const serviceShareSchema = z.object({
  service: z.string(),
  flows: z.number(),
  bytes: z.number(),
})

// Bytes moved in one second. "other" is internal and transit traffic.
export const ratePointSchema = z.object({
  t_ms: z.number(),
  out_bytes: z.number(),
  in_bytes: z.number(),
  other_bytes: z.number(),
  packets: z.number(),
})

export const trafficViewSchema = z.object({
  enabled: z.boolean(),
  totals: totalsSchema,
  active_flows: z.number(),
  latest_ns: z.number(),
  talkers: z.array(talkerSchema),
  history: z.array(ratePointSchema).default([]),
  services: z.array(serviceShareSchema),
  flows: z.array(trafficFlowSchema),
})

export type Totals = z.infer<typeof totalsSchema>
export type TrafficFlow = z.infer<typeof trafficFlowSchema>
export type Talker = z.infer<typeof talkerSchema>
export type TrafficView = z.infer<typeof trafficViewSchema>
