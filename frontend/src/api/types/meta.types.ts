// ===================
// © Pranav Verma | 2026
// meta.types.ts
// ===================

import { z } from 'zod'

export const SOURCE_KIND_VALUES = ['tail', 'replay', 'live'] as const

export const metaSchema = z.object({
  version: z.string(),
  source: z.object({
    kind: z.enum(SOURCE_KIND_VALUES),
    detail: z.string().nullable(),
    looping: z.boolean(),
  }),
  started_unix_ms: z.number(),
  location: z.string().nullable(),
})

export type MetaResponse = z.infer<typeof metaSchema>

export function describeSource(meta: MetaResponse): string {
  const { kind, detail, looping } = meta.source
  switch (kind) {
    case 'live':
      return `live ${detail ?? ''}`.trim()
    case 'replay':
      return `replay ${detail ?? ''}${looping ? ' (loop)' : ''}`.trim()
    case 'tail':
      return 'database tail'
  }
}
