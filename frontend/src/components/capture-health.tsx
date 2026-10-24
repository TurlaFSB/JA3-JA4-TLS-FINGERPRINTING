/**
 * © Pranav Verma | 2026
 * capture-health.tsx
 */

import { useCapture } from '@/api/hooks'
import type { CaptureView } from '@/api/types'
import { formatBytes } from '@/core/lib/format'
import styles from './capture-health.module.scss'

const STATUS_TEXT: Record<CaptureView['status'], string> = {
  ok: 'reading cleanly',
  degraded: 'reading with limits',
  lossy: 'losing frames',
}

function percent(part: number, whole: number): string {
  if (whole === 0) return '0%'
  return `${((part / whole) * 100).toFixed(part / whole < 0.1 ? 2 : 1)}%`
}

function setup(view: CaptureView): string {
  if (view.mode === 'live') {
    const mode = view.promiscuous ? 'promiscuous' : 'own traffic only'
    return `live on ${view.interface ?? '?'} · ${mode} · ${view.buffer_mib ?? '?'} MiB kernel buffer`
  }
  if (view.mode === 'replay') return 'replaying a capture file'
  return 'no packet source in this process'
}

export function CaptureHealth(): React.ReactElement | null {
  const { data: view } = useCapture()
  if (!view || view.mode === 'tail') return null

  const c = view.counters
  const handshakes = c.tls_handshakes_fingerprinted + c.unfinished_tls_streams
  const cells: { label: string; value: string; title: string }[] = [
    {
      label: 'frames read',
      value: c.frames.toLocaleString(),
      title: `${formatBytes(c.bytes)} through the engine`,
    },
    {
      label: 'handshakes read',
      value: c.tls_handshakes_fingerprinted.toLocaleString(),
      title: 'TLS hellos read in full',
    },
    {
      label: 'ended unread',
      value: percent(c.unfinished_tls_streams, handshakes),
      title: 'TLS streams that ended before a full handshake was read',
    },
    {
      label: 'quic opened',
      value: percent(c.quic_decrypted, c.quic_initials),
      title: 'Client Initials opened; server Initials cannot be opened passively',
    },
    {
      label: 'kernel drops',
      value: view.kernel
        ? (view.kernel.dropped + view.kernel.interface_dropped).toLocaleString()
        : 'n/a',
      title: 'Frames the operating system discarded because the reader lagged',
    },
    {
      label: 'table shed',
      value: c.flows_evicted_pressure.toLocaleString(),
      title: `Conversations dropped because the ${view.limits.max_flows.toLocaleString()}-entry table was full`,
    },
  ]

  return (
    <section
      className={styles.panel}
      data-status={view.status}
      aria-label="Capture health"
    >
      <header className={styles.head}>
        <span className={styles.badge}>{STATUS_TEXT[view.status]}</span>
        <span className={styles.setup}>{setup(view)}</span>
      </header>
      <dl className={styles.cells}>
        {cells.map((cell) => (
          <div key={cell.label} className={styles.cell} title={cell.title}>
            <dd>{cell.value}</dd>
            <dt>{cell.label}</dt>
          </div>
        ))}
      </dl>
      {view.filter && (
        <p className={styles.line}>
          <span>filter</span> <code>{view.filter}</code>
        </p>
      )}
      <p className={styles.line}>
        <span>limits</span> {view.limits.max_flows.toLocaleString()} conversations
        · idle {view.limits.idle_timeout_secs}s · {view.limits.stream_limit_kib}{' '}
        KiB per stream
      </p>
      {view.notes.length > 0 && (
        <ul className={styles.notes}>
          {view.notes.map((note) => (
            <li key={note.text} data-level={note.level}>
              {note.text}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
