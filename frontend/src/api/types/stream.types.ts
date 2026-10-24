// ===================
// ©AngelaMos | 2026
// stream.types.ts
// ===================

import { z } from 'zod'
import { alertSchema } from './alert.types'
import { type FpKind, ja4FamilySchema } from './common.types'
import { matchReportSchema } from './intel.types'

const namedSchema = z.object({ id: z.number(), name: z.string() })

// What a ClientHello offered, in words, in wire order.
export const clientDetailSchema = z.object({
  legacy_version: z.string(),
  versions: z.array(z.string()),
  ciphers: z.array(namedSchema),
  extensions: z.array(namedSchema),
  groups: z.array(namedSchema),
  signature_algorithms: z.array(namedSchema),
  ec_point_formats: z.array(z.number()),
  alpn: z.array(z.string()),
  features: z.array(z.string()),
  grease: z.boolean(),
})

export const serverDetailSchema = z.object({
  version: z.string(),
  cipher: namedSchema,
  extensions: z.array(namedSchema),
  alpn: z.string().nullable(),
})

export type ClientDetail = z.infer<typeof clientDetailSchema>
export type ServerDetail = z.infer<typeof serverDetailSchema>

const baseEventSchema = z.object({
  ts_nanos: z.number(),
  src: z.string(),
  dst: z.string(),
})

export const streamEventSchema = z.discriminatedUnion('kind', [
  baseEventSchema.extend({
    kind: z.literal('client_hello'),
    ja3: z.string(),
    ja3_raw: z.string(),
    ja4: ja4FamilySchema,
    sni: z.string().optional(),
    alpn: z.string().optional(),
    detail: clientDetailSchema.optional(),
  }),
  baseEventSchema.extend({
    kind: z.literal('server_hello'),
    ja3s: z.string(),
    ja3s_raw: z.string(),
    ja4s: ja4FamilySchema,
    detail: serverDetailSchema.optional(),
  }),
  baseEventSchema.extend({
    kind: z.literal('certificate'),
    ja4x: z.string(),
  }),
  baseEventSchema.extend({
    kind: z.literal('http_request'),
    ja4h: ja4FamilySchema,
    method: z.string(),
    host: z.string().optional(),
    user_agent: z.string().optional(),
  }),
  baseEventSchema.extend({
    kind: z.literal('tcp_syn'),
    ja4t: z.string(),
  }),
  baseEventSchema.extend({
    kind: z.literal('tcp_syn_ack'),
    ja4ts: z.string(),
  }),
])

export type StreamEvent = z.infer<typeof streamEventSchema>

export type EventKind = StreamEvent['kind']

// Who a ClientHello appears to come from, worked out by the sensor: an exact
// intelligence match when there is one, otherwise the family its shape suggests.
export const clientReadSchema = z.object({
  known_as: z.string().nullable(),
  family: z.string(),
  family_name: z.string(),
  confidence: z.enum(['high', 'medium', 'low']),
  reasons: z.array(z.string()),
  caveat: z.string().nullable(),
})

export type ClientRead = z.infer<typeof clientReadSchema>

export const liveMessageSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('flow'),
    event: streamEventSchema,
    intel: z.array(matchReportSchema).optional(),
    alerts: z.array(alertSchema).optional(),
    client: clientReadSchema.optional(),
  }),
  z.object({
    type: z.literal('alert'),
    alert: alertSchema,
  }),
])

export type LiveMessage = z.infer<typeof liveMessageSchema>

export type NamedFingerprint = {
  kind: FpKind
  value: string
}

export const isLiveMessage = (data: unknown): data is LiveMessage => {
  return liveMessageSchema.safeParse(data).success
}
