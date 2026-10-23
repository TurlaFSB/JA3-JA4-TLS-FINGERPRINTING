// ===================
// © Pranav Verma | 2026
// library.types.ts
// ===================

import { z } from 'zod'
import { verdictSchema } from './common.types'

export const guessSchema = z.object({
  family: z.enum([
    'chromium',
    'firefox',
    'safari_like',
    'open_ssl',
    'library',
    'unknown',
  ]),
  confidence: z.enum(['high', 'medium', 'low']),
  reasons: z.array(z.string()),
  caveat: z.string().nullable(),
})

export const libraryClientSchema = z.object({
  ja4: z.string(),
  transport: z.enum(['tcp', 'quic']),
  connections: z.number(),
  ja3_variants: z.number(),
  alpn: z.string().nullable(),
  servers: z.array(z.string()),
  known_as: z.string().nullable(),
  verdict: verdictSchema.nullable(),
  guess: guessSchema,
})

export const headlineSchema = z.object({
  ja4: z.string(),
  text: z.string(),
  basis: z.enum(['exact', 'inferred']),
  confidence: z.enum(['high', 'medium', 'low']),
  caveat: z.string().nullable(),
})

export const captureSchema = z.object({
  id: z.string(),
  name: z.string(),
  size: z.number(),
  modified_unix: z.number(),
  status: z.enum(['ready', 'error', 'too_large']),
  error: z.string().nullable(),
  frames: z.number(),
  tls_handshakes: z.number(),
  quic_initials: z.number(),
  first_ts_nanos: z.number().nullable(),
  last_ts_nanos: z.number().nullable(),
  clients: z.array(libraryClientSchema),
  headline: headlineSchema.nullable(),
})

export const libraryViewSchema = z.object({
  directories: z.number(),
  scanning: z.boolean(),
  scanned_unix: z.number().nullable(),
  files: z.array(captureSchema),
})

export type LibraryClient = z.infer<typeof libraryClientSchema>
export type Capture = z.infer<typeof captureSchema>
export type LibraryView = z.infer<typeof libraryViewSchema>
