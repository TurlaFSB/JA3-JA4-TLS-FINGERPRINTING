/**
 * © Pranav Verma | 2026
 * conversations.tsx
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { TrafficFlow } from '@/api/types'
import { ROUTES } from '@/config'
import { formatBytes, formatDuration } from '@/core/lib/format'
import { useClock } from '@/core/lib/use-clock'
import styles from './conversations.module.scss'
import {
  byDomain,
  clientEndpoint,
  DIRECTION_NOTE,
  describeFlow,
  identity,
  protocolWords,
  serverEndpoint,
} from './traffic-data'

const SHOWN = 200

const DIRECTION_WORDS: Record<TrafficFlow['direction'], string> = {
  outbound: 'out',
  inbound: 'in',
  internal: 'local',
  transit: 'passing',
}

function End({
  primary,
  secondary,
  tag,
}: {
  primary: string
  secondary: string
  tag: string
}): React.ReactElement {
  return (
    <span className={styles.end}>
      <span className={styles.primary} title={primary}>
        {primary}
      </span>
      <span className={styles.secondary} title={secondary}>
        {secondary}
        {tag !== '' && <span className={styles.tag}>{tag}</span>}
      </span>
    </span>
  )
}

function Fact({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}): React.ReactElement {
  return (
    <div className={styles.fact}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function Detail({ flow }: { flow: TrafficFlow }): React.ReactElement {
  const clock = useClock()
  const from = clientEndpoint(flow)
  const to = serverEndpoint(flow)
  const name = to.tag === '' ? null : to.primary
  return (
    <div className={styles.detail}>
      <p className={styles.sentence}>{describeFlow(flow)}</p>

      <div className={styles.cols}>
        <section className={styles.block}>
          <h4 className={styles.heading}>from (opened it)</h4>
          <dl className={styles.facts}>
            <Fact label="name">
              {from.tag === '' ? 'not known' : from.primary}
              {from.tag !== '' && <span className={styles.tag}>{from.tag}</span>}
            </Fact>
            <Fact label="address">{from.secondary}</Fact>
          </dl>
        </section>

        <section className={styles.block}>
          <h4 className={styles.heading}>to (answered)</h4>
          <dl className={styles.facts}>
            <Fact label="name">
              {name ?? 'not known'}
              {to.tag !== '' && <span className={styles.tag}>{to.tag}</span>}
            </Fact>
            <Fact label="address">
              {to.secondary.startsWith('port') ? flow.server : to.secondary}
            </Fact>
            {flow.service && <Fact label="service">{flow.service}</Fact>}
          </dl>
        </section>

        <section className={styles.block}>
          <h4 className={styles.heading}>protocol</h4>
          <dl className={styles.facts}>
            <Fact label="transport">{flow.proto.toUpperCase()}</Fact>
            {flow.tls_version && (
              <Fact label="tls version">{flow.tls_version}</Fact>
            )}
            {flow.cipher && <Fact label="cipher">{flow.cipher}</Fact>}
            {flow.alpn && <Fact label="alpn">{flow.alpn}</Fact>}
            {flow.ssh_banner && <Fact label="ssh">{flow.ssh_banner}</Fact>}
            {flow.http_method && (
              <Fact label="http">
                {flow.http_method} {flow.http_host ?? ''}
              </Fact>
            )}
            {flow.user_agent && <Fact label="user-agent">{flow.user_agent}</Fact>}
            {flow.client_info && (
              <Fact label="client">
                {flow.client_info.known_as
                  ? `${flow.client_info.known_as} (exact match in the feed)`
                  : `${flow.client_info.family} family (inferred from the handshake)`}
              </Fact>
            )}
            {flow.ja4 && (
              <Fact label="ja4">
                {flow.ja4}{' '}
                <Link to={`${ROUTES.SCOPE}?q=${encodeURIComponent(flow.ja4)}`}>
                  in the live stream
                </Link>
              </Fact>
            )}
            {flow.ja4s && <Fact label="ja4s">{flow.ja4s}</Fact>}
            {flow.hassh && <Fact label="hassh">{flow.hassh}</Fact>}
          </dl>
        </section>

        <section className={styles.block}>
          <h4 className={styles.heading}>volume and timing</h4>
          <dl className={styles.facts}>
            <Fact label="direction">
              {flow.direction}: {DIRECTION_NOTE[flow.direction]}
            </Fact>
            <Fact label="sent">
              {formatBytes(flow.bytes_up)} in {flow.packets_up.toLocaleString()}{' '}
              packets
            </Fact>
            <Fact label="received">
              {formatBytes(flow.bytes_down)} in{' '}
              {flow.packets_down.toLocaleString()} packets
            </Fact>
            <Fact label="state">{flow.state}</Fact>
            <Fact label="started">{clock(flow.first_ns)}</Fact>
            <Fact label="last packet">{clock(flow.last_ns)}</Fact>
            <Fact label="lasted">
              {formatDuration(flow.last_ns - flow.first_ns)}
            </Fact>
          </dl>
        </section>
      </div>

      <div className={styles.links}>
        {name && (
          <Link to={`${ROUTES.DNS}?q=${encodeURIComponent(name)}`}>
            DNS lookups for {name}
          </Link>
        )}
        <Link
          to={`${ROUTES.HOSTS}?ip=${encodeURIComponent(from.secondary.split(':')[0])}`}
        >
          history of this client
        </Link>
      </div>
    </div>
  )
}

export function Conversations({
  flows,
  total,
}: {
  flows: TrafficFlow[]
  total: number
}): React.ReactElement {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div className={styles.table}>
      <div className={styles.head} aria-hidden="true">
        <span />
        <span>from (opened it)</span>
        <span>to (answered)</span>
        <span>what</span>
        <span>client software</span>
        <span className={styles.num}>sent</span>
        <span className={styles.num}>received</span>
        <span className={styles.num}>lasted</span>
      </div>
      {flows.slice(0, SHOWN).map((flow) => {
        const key = `${flow.proto}-${flow.client}-${flow.server}`
        const expanded = open === key
        const from = clientEndpoint(flow)
        const to = serverEndpoint(flow)
        return (
          <div key={key} className={styles.item}>
            <button
              type="button"
              className={styles.row}
              data-direction={flow.direction}
              aria-expanded={expanded}
              onClick={() => setOpen(expanded ? null : key)}
            >
              <span
                className={styles.dir}
                data-direction={flow.direction}
                title={`${flow.direction}: ${DIRECTION_NOTE[flow.direction]}`}
              >
                {DIRECTION_WORDS[flow.direction]}
              </span>
              <End {...from} />
              <End {...to} />
              <span className={styles.what} title={protocolWords(flow)}>
                {protocolWords(flow)}
              </span>
              <span className={styles.who} title={identity(flow)}>
                {identity(flow)}
              </span>
              <span className={styles.num}>{formatBytes(flow.bytes_up)}</span>
              <span className={styles.num}>{formatBytes(flow.bytes_down)}</span>
              <span className={styles.num} data-state={flow.state}>
                {formatDuration(flow.last_ns - flow.first_ns)}
              </span>
            </button>
            {expanded && <Detail flow={flow} />}
          </div>
        )
      })}
      {total > SHOWN && (
        <p className={styles.more}>
          {(total - SHOWN).toLocaleString()} more match; narrow the filter to see
          them
        </p>
      )}
    </div>
  )
}

// The conversations grouped by who answered: one row per domain (or address).
export function Domains({
  flows,
  onPick,
}: {
  flows: TrafficFlow[]
  onPick: (name: string) => void
}): React.ReactElement {
  const clock = useClock()
  const rows = byDomain(flows)
  return (
    <div className={styles.table}>
      <div className={styles.domainHead} aria-hidden="true">
        <span>domain (answered)</span>
        <span className={styles.num}>talks</span>
        <span className={styles.num}>machines</span>
        <span>what</span>
        <span>client software</span>
        <span className={styles.num}>sent</span>
        <span className={styles.num}>received</span>
        <span className={styles.num}>last</span>
      </div>
      {rows.slice(0, SHOWN).map((row) => (
        <button
          key={`${row.tag}|${row.name}`}
          type="button"
          className={styles.domainRow}
          title="Show these conversations"
          onClick={() => onPick(row.name)}
        >
          <span className={styles.end}>
            <span className={styles.primary} title={row.name}>
              {row.name}
            </span>
            <span className={styles.secondary} title={row.addresses.join(', ')}>
              {row.addresses.length === 1
                ? row.addresses[0]
                : `${row.addresses.length} addresses`}
              {row.tag !== '' && <span className={styles.tag}>{row.tag}</span>}
            </span>
          </span>
          <span className={styles.num}>{row.conversations}</span>
          <span className={styles.num}>{row.clients}</span>
          <span className={styles.what} title={row.protocols.join(', ')}>
            {row.protocols.join(', ')}
          </span>
          <span className={styles.who} title={row.software.join(', ')}>
            {row.software.join(', ')}
          </span>
          <span className={styles.num}>{formatBytes(row.bytesUp)}</span>
          <span className={styles.num}>{formatBytes(row.bytesDown)}</span>
          <span className={styles.num}>{clock(row.lastNs).slice(0, 8)}</span>
        </button>
      ))}
    </div>
  )
}
