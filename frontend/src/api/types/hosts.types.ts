// ===================
// © Pranav Verma | 2026
// hosts.types.ts
// ===================

import { z } from 'zod'
import { alertSchema } from './alert.types'
import { verdictSchema } from './common.types'

export const hostSummarySchema = z.object({
  ip: z.string(),
  first_ts: z.number(),
  last_ts: z.number(),
  observations: z.number(),
  clients: z.number(),
  servers: z.number(),
  alerts: z.number(),
  verdict: verdictSchema.nullable(),
  top_label: z.string().nullable(),
})

export const clientSpanSchema = z.object({
  ja4: z.string(),
  label: z.string().nullable(),
  verdict: verdictSchema.nullable(),
  first_ts: z.number(),
  last_ts: z.number(),
  count: z.number(),
  servers: z.array(z.string()),
})

export const countedSchema = z.object({
  value: z.string(),
  count: z.number(),
})

export const hostProfileSchema = z.object({
  summary: hostSummarySchema,
  clients: z.array(clientSpanSchema),
  servers: z.array(countedSchema),
  user_agents: z.array(countedSchema),
  os_claims: z.array(countedSchema),
  alerts: z.array(alertSchema),
})

export type HostSummary = z.infer<typeof hostSummarySchema>
export type ClientSpan = z.infer<typeof clientSpanSchema>
export type HostProfile = z.infer<typeof hostProfileSchema>
