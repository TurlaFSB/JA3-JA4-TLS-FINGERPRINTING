/**
 * ©AngelaMos | 2026
 * live-stream.tsx
 */

import { useEffect, useMemo, useRef, useState } from 'react'
import type { LiveItem } from '@/api/hooks'
import {
  type Alert,
  type ClientRead,
  fingerprintOf,
  type MatchReport,
  type Severity,
  type StreamEvent,
  splitAddr,
  worstVerdict,
} from '@/api/types'
import { useClock } from '@/core/lib/use-clock'
import { SeverityTag } from './atoms'
import { cx } from './cx'
import { EventDetail } from './event-detail'
import styles from './live-stream.module.scss'
import { CropFrame } from './marks'
import {
  buildConnections,
  bySite,
  type Connection,
  clientName,
  connectionKey,
  leadAlert,
  matchesSite,
  NO_NAME,
  RULE_NOTE,
  RULE_SHORT,
  type SiteRow,
} from './stream-data'

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
  ssh: 'SSH',
}

type FilterId =
  | 'tls'
  | 'all'
  | 'client'
  | 'server'
  | 'cert'
  | 'http'
  | 'tcp'
  | 'ssh'
  | 'alert'

const FILTERS: { id: FilterId; label: string }[] = [
  { id: 'tls', label: 'handshakes' },
  { id: 'client', label: 'client' },
  { id: 'server', label: 'server' },
  { id: 'cert', label: 'cert' },
  { id: 'http', label: 'http' },
  { id: 'tcp', label: 'tcp' },
  { id: 'ssh', label: 'ssh' },
  { id: 'alert', label: 'alerts' },
  { id: 'all', label: 'everything' },
]

const KIND_FILTER: Record<StreamEvent['kind'], FilterId> = {
  client_hello: 'client',
  server_hello: 'server',
  certificate: 'cert',
  http_request: 'http',
  tcp_syn: 'tcp',
  tcp_syn_ack: 'tcp',
  ssh: 'ssh',
}

function searchText(item: LiveItem): string {
  const { message } = item
  if (message.type === 'alert') {
    return `${message.alert.title} ${message.alert.ip ?? ''}`.toLowerCase()
  }
  const { event } = message
  const sni = 'sni' in event ? (event.sni ?? '') : ''
  const who = message.client ? clientName(message.client).text : ''
  return `${event.src} ${event.dst} ${fingerprintOf(event).value} ${sni} ${who}`.toLowerCase()
}

function matches(item: LiveItem, filter: FilterId, query: string): boolean {
  const { message } = item
  const group =
    message.type === 'alert' ? 'alert' : KIND_FILTER[message.event.kind]
  if (filter === 'tls') {
    // Handshakes and requests: everything except raw TCP SYN rows, which
    // outnumber them and say little on their own.
    if (group === 'tcp') return false
  } else if (filter !== 'all' && group !== filter) {
    return false
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
  client,
  conn,
  selected,
  animate,
  onSelect,
}: {
  animate: boolean
  event: StreamEvent
  intel?: MatchReport[]
  alerts?: Alert[]
  client?: ClientRead
  conn?: Connection
  selected: boolean
  onSelect: () => void
}): React.ReactElement {
  const clock = useClock()
  const fingerprint = fingerprintOf(event)
  const src = splitAddr(event.src)
  const dst = splitAddr(event.dst)
  const verdict = worstVerdict(intel)
  const lead = leadAlert(alerts)
  const severity = topSeverity(alerts ?? [])
  const hot = severity === 'high' || severity === 'critical'
  const own =
    event.kind === 'ssh'
      ? event.banner.replace(/^SSH-[0-9.]+-/, '')
      : 'sni' in event
        ? event.sni
        : undefined
  // A server's reply carries no name of its own; take it from the connection
  // it answers, and say so by dimming it.
  const borrowed = own === undefined && event.kind !== 'client_hello'
  const sni = own ?? conn?.sni
  const who = clientName(client ?? conn?.client)

  return (
    <button
      type="button"
      className={cx(styles.row, animate && styles.enter, hot && styles.rowHot)}
      data-verdict={verdict ?? 'unknown'}
      data-selected={selected}
      onClick={onSelect}
      aria-pressed={selected}
      aria-label={`${KIND_CODE[event.kind]} ${sni ?? event.dst}, open details`}
    >
      <span className={styles.time}>{clock(event.ts_nanos)}</span>
      <span className={styles.code}>{KIND_CODE[event.kind]}</span>
      <span className={styles.route} title={`${event.src} -> ${event.dst}`}>
        <span className={styles.host}>{src.host}</span>
        <span className={styles.arrow}>-&gt;</span>
        <span className={styles.host}>{dst.host}</span>
      </span>
      <span
        className={cx(styles.sni, borrowed && styles.borrowed)}
        title={
          sni
            ? `${sni}${borrowed ? ' (from the matching client hello)' : ''}`
            : undefined
        }
      >
        {sni ?? (event.kind === 'client_hello' ? '(no server name)' : '')}
      </span>
      <span
        className={cx(styles.who, borrowed && styles.borrowed)}
        data-basis={who.basis}
        title={
          who.basis === 'inferred'
            ? 'Inferred from the shape of the handshake, not matched exactly'
            : who.basis === 'exact'
              ? 'Matched exactly in the intelligence feed'
              : undefined
        }
      >
        {who.text}
      </span>
      <span className={styles.fp} title={fingerprint.value}>
        <span className={styles.fpKind}>
          {fingerprint.kind.replace('_', ' ')}
        </span>
        <span className={styles.fpValue}>{fingerprint.value}</span>
      </span>
      <span className={styles.marks}>
        {verdict && (
          <span className={styles.verdict} data-verdict={verdict}>
            {verdict}
          </span>
        )}
        {lead && severity && (
          <span
            className={styles.tag}
            data-sev={severity}
            title={`${lead.title}. ${RULE_NOTE[lead.rule]}`}
          >
            {RULE_SHORT[lead.rule]}
            {(alerts?.length ?? 0) > 1 ? ` +${(alerts?.length ?? 1) - 1}` : ''}
          </span>
        )}
      </span>
    </button>
  )
}

function SiteTable({
  rows,
  onPick,
}: {
  rows: SiteRow[]
  onPick: (site: string) => void
}): React.ReactElement {
  const clock = useClock()
  return (
    <div className={styles.sites}>
      <div className={cx(styles.siteRow, styles.siteHead)} aria-hidden="true">
        <span>site</span>
        <span>clients that reached it</span>
        <span className={styles.num}>conn.</span>
        <span className={styles.num}>quic</span>
        <span className={styles.num}>last</span>
      </div>
      {rows.map((row) => (
        <button
          key={row.site}
          type="button"
          className={styles.siteRow}
          data-verdict={row.verdict ?? 'unknown'}
          onClick={() => onPick(row.site)}
          title="Show the handshakes for this site"
        >
          <span className={styles.siteName}>
            {row.site}
            {row.alerts > 0 && (
              <span className={styles.siteAlerts}>{row.alerts} alert(s)</span>
            )}
          </span>
          <span className={styles.siteClients}>
            {row.clients.slice(0, 3).map((client) => (
              <span key={client.ja4} className={styles.siteClient}>
                <span className={styles.who} data-basis={client.name.basis}>
                  {client.name.text || 'unnamed'}
                </span>
                <span className={styles.siteJa4} title={client.ja4}>
                  {client.ja4}
                </span>
                {client.connections > 1 && (
                  <span className={styles.siteCount}>x{client.connections}</span>
                )}
              </span>
            ))}
            {row.clients.length > 3 && (
              <span className={styles.siteMore}>
                +{row.clients.length - 3} more fingerprint(s)
              </span>
            )}
          </span>
          <span className={styles.num}>{row.connections}</span>
          <span className={styles.num}>{row.quic}</span>
          <span className={styles.num}>{clock(row.lastTs).slice(0, 8)}</span>
        </button>
      ))}
    </div>
  )
}

function AlertRow({
  alert,
  animate,
}: {
  alert: Alert
  animate: boolean
}): React.ReactElement {
  const clock = useClock()
  return (
    <div
      className={cx(styles.row, animate && styles.enter, styles.alertRow)}
      data-sev={alert.severity}
    >
      <span className={styles.time}>{clock(alert.ts_nanos)}</span>
      <span className={cx(styles.code, styles.codeAlert)}>ALR</span>
      <span className={styles.alertTitle}>{alert.title}</span>
      <span className={styles.marks}>
        <SeverityTag severity={alert.severity} />
      </span>
    </div>
  )
}

function StreamBody({
  view,
  sites,
  items,
  feedEmpty,
  connections,
  selectedSeq,
  onSelect,
  onPickSite,
}: {
  view: 'events' | 'sites'
  sites: SiteRow[]
  items: LiveItem[]
  feedEmpty: boolean
  connections: Map<string, Connection>
  selectedSeq?: number
  onSelect: (item: LiveItem) => void
  onPickSite: (site: string) => void
}): React.ReactElement {
  if (view === 'sites') {
    return (
      <div className={styles.scroll}>
        {sites.length === 0 ? (
          <div className={styles.idle}>
            <span className={styles.idleLine}>no sites yet</span>
            <span className={styles.idleSub}>
              sites appear as clients start TLS or QUIC connections
            </span>
          </div>
        ) : (
          <SiteTable rows={sites} onPick={onPickSite} />
        )}
      </div>
    )
  }
  if (items.length === 0) {
    return (
      <div className={styles.scroll}>
        <div className={styles.idle}>
          <span className={styles.idleLine}>
            {feedEmpty
              ? 'awaiting handshakes on the wire'
              : 'no events match this filter'}
          </span>
          <span className={styles.idleSub}>
            {feedEmpty
              ? 'nothing has crossed the scope yet. replay a capture or start a live sensor'
              : 'clear the filter to see the full stream'}
          </span>
        </div>
      </div>
    )
  }
  return (
    <div className={styles.scroll}>
      {items.map((item) =>
        item.message.type === 'flow' ? (
          <FlowRow
            key={item.seq}
            event={item.message.event}
            intel={item.message.intel}
            alerts={item.message.alerts}
            client={item.message.client}
            conn={connections.get(connectionKey(item.message.event))}
            animate={item.animate}
            selected={selectedSeq === item.seq}
            onSelect={() => onSelect(item)}
          />
        ) : (
          <AlertRow
            key={item.seq}
            alert={item.message.alert}
            animate={item.animate}
          />
        )
      )}
    </div>
  )
}

export function LiveStream({
  feed,
  connected,
  flowCount,
  query,
  onQuery,
  className,
}: {
  feed: LiveItem[]
  connected: boolean
  flowCount: number
  query: string
  onQuery: (value: string) => void
  className?: string
}): React.ReactElement {
  const [view, setView] = useState<'events' | 'sites'>('events')
  const [filter, setFilter] = useState<FilterId>('tls')
  const [frozen, setFrozen] = useState<LiveItem[] | null>(null)
  const [selected, setSelected] = useState<LiveItem | null>(null)
  // Clearing hides everything seen so far without touching the running counts.
  const [clearedThrough, setClearedThrough] = useState(0)

  const searchRef = useRef<HTMLInputElement>(null)

  // "/" jumps to the filter box from anywhere that is not already a text field.
  useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      const target = event.target as HTMLElement | null
      const typing =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement
      if (event.key === '/' && !typing) {
        event.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

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

  const connections = useMemo(() => buildConnections(source), [source])
  const sites = useMemo(
    () => bySite(source).filter((row) => matchesSite(row, needle)),
    [source, needle]
  )

  const flowItems = useMemo(
    () => items.filter((item) => item.message.type === 'flow'),
    [items]
  )
  const selectedIndex = selected
    ? flowItems.findIndex((item) => item.seq === selected.seq)
    : -1
  const step = (delta: number): void => {
    const next = flowItems[selectedIndex + delta]
    if (next) setSelected(next)
  }

  const aside = (
    <span className={styles.aside}>
      <span className={cx(styles.live, connected && !paused && styles.liveOn)}>
        {!connected ? 'down' : paused ? 'paused' : 'rec'}
      </span>
      <span className={styles.count}>
        {view === 'sites'
          ? `${sites.length.toLocaleString()} sites`
          : items.length === source.length
            ? `${flowCount.toLocaleString()} flows`
            : `${items.length.toLocaleString()} shown / ${flowCount.toLocaleString()} flows`}
      </span>
    </span>
  )

  const selectedFlow =
    selected && selected.message.type === 'flow' ? selected.message : null

  return (
    <CropFrame
      label="live stream"
      aside={aside}
      className={cx(styles.frame, className)}
    >
      <div className={styles.controls}>
        <fieldset className={styles.views}>
          <legend className={styles.srOnly}>View</legend>
          {(
            [
              ['events', 'events'],
              ['sites', 'by site'],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={cx(styles.chip, view === id && styles.chipOn)}
              aria-pressed={view === id}
              onClick={() => setView(id)}
            >
              {label}
            </button>
          ))}
        </fieldset>
        <fieldset className={styles.filters} hidden={view === 'sites'}>
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
          ref={searchRef}
          id="live-stream-filter"
          placeholder="filter ip, site, client, fingerprint  ( / )"
          aria-label="Filter the live stream"
          value={query}
          onChange={(event) => onQuery(event.target.value)}
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

      <StreamBody
        view={view}
        sites={sites}
        items={items}
        feedEmpty={feed.length === 0}
        connections={connections}
        selectedSeq={selected?.seq}
        onSelect={(item) => setSelected(selected?.seq === item.seq ? null : item)}
        onPickSite={(site) => {
          onQuery(site === NO_NAME ? '' : site)
          setFilter('client')
          setView('events')
        }}
      />

      {selectedFlow && (
        <EventDetail
          event={selectedFlow.event}
          intel={selectedFlow.intel}
          alerts={selectedFlow.alerts}
          client={selectedFlow.client}
          conn={connections.get(connectionKey(selectedFlow.event))}
          onClose={() => setSelected(null)}
          onFilter={(value) => {
            onQuery(value)
            setView('events')
            setFilter('all')
            setSelected(null)
          }}
          onOpen={(seq) => {
            const target = source.find((item) => item.seq === seq)
            if (target) setSelected(target)
          }}
          onPrev={selectedIndex > 0 ? () => step(-1) : undefined}
          onNext={
            selectedIndex >= 0 && selectedIndex < flowItems.length - 1
              ? () => step(1)
              : undefined
          }
          position={
            selectedIndex >= 0
              ? `${selectedIndex + 1} of ${flowItems.length}`
              : undefined
          }
        />
      )}
    </CropFrame>
  )
}
