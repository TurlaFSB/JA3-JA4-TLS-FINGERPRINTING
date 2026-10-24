/**
 * © Pranav Verma | 2026
 * traffic-mix.tsx
 */

import { useMemo } from 'react'
import type { LiveItem } from '@/api/hooks'
import { worstVerdict } from '@/api/types'
import { cx } from './cx'
import styles from './distribution.module.scss'
import { CropFrame } from './marks'

interface Row {
  label: string
  count: number
}

function tally(values: string[], limit = 6): Row[] {
  const counts = new Map<string, number>()
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1)
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit)
}

// The JA4 version field: 13 is TLS 1.3, 12 is TLS 1.2, and so on.
const VERSIONS: Record<string, string> = {
  '13': 'TLS 1.3',
  '12': 'TLS 1.2',
  '11': 'TLS 1.1',
  '10': 'TLS 1.0',
}

export interface Mix {
  total: number
  verdicts: Row[]
  transport: Row[]
  versions: Row[]
  alpn: Row[]
  servers: Row[]
}

// What the sensor has been seeing, from the client hellos in the live window.
// Every figure is a count of those handshakes, not of the intelligence feed.
export function summariseMix(feed: LiveItem[]): Mix {
  const verdicts: string[] = []
  const transport: string[] = []
  const versions: string[] = []
  const alpn: string[] = []
  const servers: string[] = []
  for (const { message } of feed) {
    if (message.type !== 'flow' || message.event.kind !== 'client_hello') continue
    const { event } = message
    verdicts.push(worstVerdict(message.intel) ?? 'unknown')
    transport.push(event.ja4.hash.startsWith('q') ? 'QUIC' : 'TCP')
    versions.push(VERSIONS[event.ja4.hash.slice(1, 3)] ?? 'other')
    alpn.push(event.alpn ?? 'none offered')
    if (event.sni) servers.push(event.sni)
  }
  return {
    total: verdicts.length,
    verdicts: tally(verdicts),
    transport: tally(transport),
    versions: tally(versions),
    alpn: tally(alpn),
    servers: tally(servers, 8),
  }
}

function Group({
  title,
  rows,
  total,
  attr,
}: {
  title: string
  rows: Row[]
  total: number
  attr?: string
}): React.ReactElement {
  return (
    <div className={styles.group}>
      <div className={styles.groupHead}>{title}</div>
      {rows.length === 0 ? (
        <div className={styles.empty}>none yet</div>
      ) : (
        rows.map((row) => (
          <div
            key={row.label}
            className={styles.bar}
            data-plain=""
            {...(attr ? { [attr]: row.label } : {})}
          >
            <span className={styles.barLabel} title={row.label}>
              {row.label}
            </span>
            <span className={styles.track}>
              <span
                className={styles.fill}
                style={{
                  width: `${Math.max(2.5, (row.count / Math.max(1, total)) * 100)}%`,
                }}
              />
            </span>
            <span className={styles.value}>{row.count.toLocaleString()}</span>
          </div>
        ))
      )}
    </div>
  )
}

export function TrafficMix({
  feed,
  className,
}: {
  feed: LiveItem[]
  className?: string
}): React.ReactElement {
  const mix = useMemo(() => summariseMix(feed), [feed])
  return (
    <CropFrame
      label="what the sensor sees"
      aside={
        <span className={styles.note}>
          {mix.total.toLocaleString()} client hellos in the window
        </span>
      }
      className={cx(styles.frame, className)}
    >
      <div className={styles.body}>
        <Group
          title="intelligence verdict"
          rows={mix.verdicts}
          total={mix.total}
          attr="data-verdict"
        />
        <Group title="transport" rows={mix.transport} total={mix.total} />
        <Group title="tls version" rows={mix.versions} total={mix.total} />
        <Group title="application protocol" rows={mix.alpn} total={mix.total} />
        <Group
          title="most requested servers"
          rows={mix.servers}
          total={mix.total}
        />
      </div>
    </CropFrame>
  )
}
