// ===================
// © Pranav Verma | 2026
// capture.types.ts
// ===================

import { z } from 'zod'

const countersSchema = z.object({
  frames: z.number(),
  bytes: z.number(),
  tcp_segments: z.number(),
  udp_datagrams: z.number(),
  skipped_malformed: z.number(),
  flows_created: z.number(),
  flows_evicted_idle: z.number(),
  flows_evicted_pressure: z.number(),
  segments_dropped: z.number(),
  streams_capped: z.number(),
  tls_handshakes_fingerprinted: z.number(),
  unfinished_tls_streams: z.number(),
  quic_initials: z.number(),
  quic_decrypted: z.number(),
})

export const captureViewSchema = z.object({
  mode: z.string(),
  interface: z.string().nullable(),
  filter: z.string().nullable(),
  promiscuous: z.boolean().nullable(),
  buffer_mib: z.number().nullable(),
  limits: z.object({
    max_flows: z.number(),
    idle_timeout_secs: z.number(),
    stream_limit_kib: z.number(),
  }),
  counters: countersSchema,
  kernel: z
    .object({
      received: z.number(),
      dropped: z.number(),
      interface_dropped: z.number(),
    })
    .nullable(),
  tls_miss_rate: z.number(),
  status: z.enum(['ok', 'degraded', 'lossy']),
  notes: z.array(z.object({ level: z.enum(['warn', 'info']), text: z.string() })),
})

export type CaptureView = z.infer<typeof captureViewSchema>
