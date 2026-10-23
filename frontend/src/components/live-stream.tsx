/**
 * ©AngelaMos | 2026
 * live-stream.tsx
 */

import { useMemo, useState } from 'react'
import type { LiveItem } from '@/api/hooks'
import {
  type Alert,
  fingerprintOf,
  formatClock,
  type MatchReport,
  type Severity,
  type StreamEvent,
  splitAddr,
  worstVerdict,
} from '@/api/types'
import { SeverityTag } from './atoms'
import { cx } from './cx'
import { EventDetail } from './event-detail'
import styles from './live-stream.module.scss'
import { CropFrame } from './marks'

const SEV_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const KIND_CODE: Record<StreamEvent['kind'], string> = {
  client_hello: 'CLT',
  server_hello: 'SRV',
  certificate: 'CRT',
  http_request: 'HTP',
  tcp_syn: 'SYN',
  tcp_syn_ack: 'SYK',
}

type FilterId = 'all' | 'client' | 'server' | 'cert' | 'http' | 'tcp' | 'alert'

const FILTERS: { id: FilterId; label: string }[] = [
  { id: 'all', label: 'all' },
  { id: 'client', label: 'client' },
  { id: 'server', label: 'server' },
  { id: 'cert', label: 'cert' },
  { id: 'http', label: 'http' },
  { id: 'tcp', label: 'tcp' },
  { id: 'alert', label: 'alerts' },
]

const KIND_FILTER: Record<StreamEvent['kind'], FilterId> = {
  client_hello: 'client',
  server_hello: 'server',
  certificate: 'cert',
  http_request: 'http',
  tcp_syn: 'tcp',
  tcp_syn_ack: 'tcp',
}

function searchText(item: LiveItem): string {
  const { message } = item
  if (message.type === 'alert') {
    return `${message.alert.title} ${message.alert.ip ?? ''}`.toLowerCase()
  }
  const { event } = message
  const sni = 'sni' in event ? (event.sni ?? '') : ''
  return `${event.src} ${event.dst} ${fingerprintOf(event).value} ${sni}`.toLowerCase()
}

function matches(item: LiveItem, filter: FilterId, query: string): boolean {
  const { message } = item
  if (filter !== 'all') {
    const group =
      message.type === 'alert' ? 'alert' : KIND_FILTER[message.event.kind]
    if (group !== filter) return false
  }
  return query === '' || searchText(item).includes(query)
}

function topSeverity(alerts: Alert[]): Severity | undefined {
  if (alerts.length === 0) return undefined
  return alerts.reduce<Severity>(
    (worst, alert) =>
      SEV_ORDER[alert.severity] > SEV_ORDER[worst] ? alert.severity : worst,
    'info'
  )
}

function FlowRow({
  event,
  intel,
  alerts,
  selected,
  animate,
  onSelect,
}: {
  animate: boolean
  event: StreamEvent
  intel?: MatchReport[]
  alerts?: Alert[]
  selected: boolean
  onSelect: () => void
}): React.ReactElement {
  const fingerprint = fingerprintOf(event)
  const src = splitAddr(event.src)
  const dst = splitAddr(event.dst)
  const verdict = worstVerdict(intel)
  const severity = topSeverity(alerts ?? [])
  const hot = severity === 'high' || severity === 'critical'
  const sni = 'sni' in event ? event.sni : undefined

  return (
    <button
      type="button"
      className={cx(styles.row, animate && styles.enter, hot && styles.rowHot)}
      data-verdict={verdict ?? 'unknown'}
      data-selected={selected}
      onClick={onSelect}
      aria-pressed={selected}
    >
      <span className={styles.time}>{formatClock(event.ts_nanos)}</span>
      <span className={styles.code}>{KIND_CODE[event.kind]}</span>
      <span className={styles.route}>
        <span className={styles.hosts}>
          <span className={styles.host}>{src.host}</span>
          <span className={styles.arrow}>-&gt;</span>
          <span className={styles.host}>{dst.host}</span>
        </span>
        {sni && <span className={styles.sni}>{sni}</span>}
      </span>
      <span className={styles.fp} title={fingerprint.value}>
        <span className={styles.fpKind}>{fingerprint.kind}</span>
        <span className={styles.fpValue}>{fingerprint.value}</span>
      </span>
      <span className={styles.marks}>
        {verdict && (
          <span className={styles.verdict} data-verdict={verdict}>
            {verdict}
          </span>
        )}
        {severity && <SeverityTag severity={severity} />}
      </span>
    </button>
  )
}

function AlertRow({
  alert,
  animate,
}: {
  alert: Alert
  animate: boolean
}): React.ReactElement {
  return (
    <div
      className={cx(styles.row, animate && styles.enter, styles.alertRow)}
      data-sev={alert.severity}
    >
      <span className={styles.time}>{formatClock(alert.ts_nanos)}</span>
      <span className={cx(styles.code, styles.codeAlert)}>ALR</span>
      <span className={styles.alertTitle}>{alert.title}</span>
      <span className={styles.marks}>
        <SeverityTag severity={alert.severity} />
      </span>
    </div>
  )
}

export function LiveStream({
  feed,
  connected,
  flowCount,
  className,
}: {
  feed: LiveItem[]
  connected: boolean
  flowCount: number
  className?: string
}): React.ReactElement {
  const [filter, setFilter] = useState<FilterId>('all')
  const [query, setQuery] = useState('')
  const [frozen, setFrozen] = useState<LiveItem[] | null>(null)
  const [selected, setSelected] = useState<LiveItem | null>(null)
  // Clearing hides everything seen so far without touching the running counts.
  const [clearedThrough, setClearedThrough] = useState(0)

  const paused = frozen !== null
  const source = frozen ?? feed
  const needle = query.trim().toLowerCase()
  const items = useMemo(
    () =>
      source.filter(
        (item) => item.seq > clearedThrough && matches(item, filter, needle)
      ),
    [source, filter, needle, clearedThrough]
  )

  const aside = (
    <span className={styles.aside}>
      <span className={cx(styles.live, connected && !paused && styles.liveOn)}>
        {!connected ? 'down' : paused ? 'paused' : 'rec'}
      </span>
      <span className={styles.count}>
        {items.length === source.length
          ? `${flowCount.toLocaleString()} flows`
          : `${items.length.toLocaleString()} shown / ${flowCount.toLocaleString()} flows`}
      </span>
    </span>
  )

  const selectedFlow =
    selected && selected.message.type === 'flow' ? selected.message : null

  return (
    <CropFrame
      label="live // passive wire-tap"
      aside={aside}
      className={cx(styles.frame, className)}
    >
      <div className={styles.controls}>
        <fieldset className={styles.filters}>
          <legend className={styles.srOnly}>Filter by event type</legend>
          {FILTERS.map((item) => (
            <button
              key={item.id}
              type="button"
              className={cx(styles.chip, filter === item.id && styles.chipOn)}
              aria-pressed={filter === item.id}
              onClick={() => setFilter(item.id)}
            >
              {item.label}
            </button>
          ))}
        </fieldset>
        <input
          type="search"
          className={styles.search}
          placeholder="filter ip, sni, fingerprint"
          aria-label="Filter the live stream"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <button
          type="button"
          className={cx(styles.chip, paused && styles.chipOn)}
          aria-pressed={paused}
          onClick={() => setFrozen(paused ? null : feed)}
        >
          {paused ? 'resume' : 'pause'}
        </button>
        <button
          type="button"
          className={styles.chip}
          onClick={() => {
            setClearedThrough(feed[0]?.seq ?? 0)
            setSelected(null)
          }}
          disabled={items.length === 0}
        >
          clear
        </button>
      </div>

      <div className={styles.scroll}>
        {items.length === 0 ? (
          <div className={styles.idle}>
            <span className={styles.idleLine}>
              {feed.length === 0
                ? 'awaiting handshakes on the wire'
                : 'no events match this filter'}
            </span>
            <span className={styles.idleSub}>
              {feed.length === 0
                ? 'nothing has crossed the scope yet. replay a capture or start a live sensor'
                : 'clear the filter to see the full stream'}
            </span>
          </div>
        ) : (
          items.map((item) =>
            item.message.type === 'flow' ? (
              <FlowRow
                key={item.seq}
                event={item.message.event}
                intel={item.message.intel}
                alerts={item.message.alerts}
                animate={item.animate}
                selected={selected?.seq === item.seq}
                onSelect={() =>
                  setSelected(selected?.seq === item.seq ? null : item)
                }
              />
            ) : (
              <AlertRow
                key={item.seq}
                alert={item.message.alert}
                animate={item.animate}
              />
            )
          )
        )}
      </div>

      {selectedFlow && (
        <EventDetail
          event={selectedFlow.event}
          intel={selectedFlow.intel}
          alerts={selectedFlow.alerts}
          onClose={() => setSelected(null)}
        />
      )}
    </CropFrame>
  )
}
