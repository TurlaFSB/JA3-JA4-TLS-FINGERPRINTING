// ===================
// © Pranav Verma | 2026
// observed.types.ts
// ===================

import { z } from 'zod'
import { verdictSchema } from './common.types'

export const knowledgeSchema = z.enum(['exact', 'partial', 'unknown'])
export type Knowledge = z.infer<typeof knowledgeSchema>

export const observedClientSchema = z.object({
  ja4: z.string(),
  connections: z.number(),
  hosts: z.number(),
  first_ts: z.number(),
  last_ts: z.number(),
  sites: z.array(z.string()),
  knowledge: knowledgeSchema,
  label: z.string().nullable(),
  source: z.string().nullable(),
  verdict: verdictSchema.nullable(),
  guess: z
    .object({
      family: z.string(),
      confidence: z.enum(['high', 'medium', 'low']),
      reasons: z.array(z.string()),
      caveat: z.string().nullable(),
    })
    .nullable(),
})

export const coverageSchema = z.object({
  fingerprints: z.number(),
  exact: z.number(),
  partial: z.number(),
  unknown: z.number(),
  connections: z.number(),
  exact_connections: z.number(),
})

export const observedSchema = z.object({
  coverage: coverageSchema,
  clients: z.array(observedClientSchema),
})

export type ObservedClient = z.infer<typeof observedClientSchema>
export type Coverage = z.infer<typeof coverageSchema>
export type Observed = z.infer<typeof observedSchema>
