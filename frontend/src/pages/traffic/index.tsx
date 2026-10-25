/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { type RateSample, useTraffic } from '@/api/hooks'
import type { Talker } from '@/api/types'
import { CaptureHealth, CropFrame, cx } from '@/components'
import { downloadText, stamp, toCsv } from '@/core/lib/export'
import { formatBitRate, formatBytes } from '@/core/lib/format'
import { Conversations } from './conversations'
import styles from './traffic.module.scss'
import {
  chartMax,
  type DirectionFilter,
  FLOW_HEADERS,
  flowRows,
  linePath,
  matchesFlow,
  type ProtoFilter,
  type SortKey,
  sortFlows,
} from './traffic-data'

const CHART_W = 600
const CHART_H = 120

function areaPath(values: number[], max: number): string {
  const line = linePath(values, CHART_W, CHART_H, max)
  return line === '' ? '' : `${line} L${CHART_W} ${CHART_H} L0 ${CHART_H} Z`
}

function spanLabel(seconds: number): string {
  if (seconds >= 120) return `${Math.round(seconds / 60)} min ago`
  return `${seconds} s ago`
}

function Throughput({ samples }: { samples: RateSample[] }): React.ReactElement {
  const ins = samples.map((s) => s.inBps)
  const outs = samples.map((s) => s.outBps)
  const others = samples.map((s) => s.otherBps)
  const peak = Math.max(0, ...ins, ...outs, ...others)
  const max = chartMax([...ins, ...outs, ...others])
  const latest = samples.at(-1)
  const quiet = samples.length > 0 && peak === 0
  return (
    <CropFrame
      label="throughput"
      aside={
        <span className={styles.aside}>
          {latest ? `scale ${formatBitRate(max)}` : 'waiting for samples'}
        </span>
      }
      className={styles.chartFrame}
    >
      <div className={styles.chartBody}>
        <div className={styles.legend}>
          <span className={styles.keyOut}>
            out {latest ? formatBitRate(latest.outBps) : '-'}
          </span>
          <span className={styles.keyIn}>
            in {latest ? formatBitRate(latest.inBps) : '-'}
          </span>
          <span
            className={styles.keyMid}
            title="Traffic between two local hosts, or two remote ones the sensor merely sees"
          >
            other {latest ? formatBitRate(latest.otherBps) : '-'}
          </span>
          <span className={styles.keyPkt}>
            {latest ? Math.round(latest.packetsPerSecond).toLocaleString() : '-'}{' '}
            pkt/s
          </span>
        </div>
        <div className={styles.plot}>
          <div className={styles.yAxis} aria-hidden="true">
            <span>{formatBitRate(max)}</span>
            <span>{formatBitRate(max / 2)}</span>
            <span>0</span>
          </div>
          <svg
            viewBox={`0 0 ${CHART_W} ${CHART_H}`}
            className={styles.chart}
            role="img"
            aria-label={`Throughput over the last ${spanLabel(samples.length)}: outbound, inbound and other`}
            preserveAspectRatio="none"
          >
            {[0.25, 0.5, 0.75].map((line) => (
              <line
                key={line}
                x1="0"
                x2={CHART_W}
                y1={CHART_H * line}
                y2={CHART_H * line}
                className={styles.grid}
              />
            ))}
            <path d={areaPath(ins, max)} className={styles.areaIn} />
            <path d={areaPath(outs, max)} className={styles.areaOut} />
            <path
              d={linePath(others, CHART_W, CHART_H, max)}
              className={styles.lineMid}
            />
            <path
              d={linePath(ins, CHART_W, CHART_H, max)}
              className={styles.lineIn}
            />
            <path
              d={linePath(outs, CHART_W, CHART_H, max)}
              className={styles.lineOut}
            />
          </svg>
          {quiet && (
            <span className={styles.quiet}>no traffic in this window</span>
          )}
        </div>
        <div className={styles.xAxis} aria-hidden="true">
          <span>{samples.length > 0 ? spanLabel(samples.length) : ''}</span>
          <span>now</span>
        </div>
      </div>
    </CropFrame>
  )
}

function Talkers({ talkers }: { talkers: Talker[] }): React.ReactElement {
  const max = Math.max(1, ...talkers.map((t) => t.bytes_up + t.bytes_down))
  return (
    <CropFrame label="top remote hosts" className={styles.sideFrame}>
      <ul className={styles.rank}>
        {talkers.length === 0 && (
          <li className={styles.none}>no conversations yet</li>
        )}
        {talkers.slice(0, 10).map((t) => {
          const total = t.bytes_up + t.bytes_down
          return (
            <li key={t.host} title={t.names.join(', ')}>
              <span className={styles.rankName}>
                {t.names[0] ?? t.host}
                {t.names[0] && <i>{t.host}</i>}
              </span>
              <span className={styles.rankBar}>
                <span style={{ width: `${Math.max(2, (total / max) * 100)}%` }} />
              </span>
              <span className={styles.rankValue}>{formatBytes(total)}</span>
            </li>
          )
        })}
      </ul>
    </CropFrame>
  )
}

const DIRECTIONS: DirectionFilter[] = [
  'all',
  'outbound',
  'inbound',
  'internal',
  'transit',
]
const PROTOS: ProtoFilter[] = ['all', 'tcp', 'udp']
const SORTS: { id: SortKey; label: string }[] = [
  { id: 'recent', label: 'recent' },
  { id: 'bytes', label: 'size' },
  { id: 'duration', label: 'duration' },
]

export function Component(): React.ReactElement {
  const { view, samples, error } = useTraffic()
  const [direction, setDirection] = useState<DirectionFilter>('all')
  const [proto, setProto] = useState<ProtoFilter>('all')
  const [namedOnly, setNamedOnly] = useState(false)
  const [params] = useSearchParams()
  const [query, setQuery] = useState(params.get('q') ?? '')
  const [sort, setSort] = useState<SortKey>('recent')

  const flows = view?.flows ?? []
  const shown = useMemo(
    () =>
      sortFlows(
        flows.filter((flow) =>
          matchesFlow(flow, { direction, proto, namedOnly, query })
        ),
        sort
      ),
    [flows, direction, proto, namedOnly, query, sort]
  )
  const filtering =
    direction !== 'all' || proto !== 'all' || namedOnly || query !== ''
  const latest = samples.at(-1)
  const totals = view?.totals

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>traffic</span>
        <h1 className={styles.title}>Traffic</h1>
        <p className={styles.sub}>
          Every conversation the sensor sees, read left to right: who opened it,
          who answered, what kind of conversation it was, and how much was sent
          and received. Names come from the best evidence available: the
          handshake, the HTTP request, a DNS answer, or a reverse lookup, and each
          says which. Click a row for the full picture. "Out" means from this
          network to another, "in" the reverse, "local" within it;{' '}
          <em>this network</em> is the capture interface's own networks plus
          private ranges (add others with --local-network).
        </p>
      </section>

      {error && <p className={styles.notice}>The server did not answer.</p>}
      {view && !view.enabled && (
        <p className={styles.notice}>
          This server has no packet source of its own, so there is no traffic to
          show. Start it with <code>--live INTERFACE</code> or{' '}
          <code>--replay FILE</code>.
        </p>
      )}

      <CaptureHealth />

      <section className={styles.stats} aria-label="Traffic totals">
        <div className={styles.stat}>
          <span className={styles.value}>
            {(view?.active_flows ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>conversations</span>
        </div>
        <div className={styles.stat} data-way="out">
          <span className={styles.value}>
            {latest ? formatBitRate(latest.outBps) : '-'}
          </span>
          <span className={styles.label}>
            out · {formatBytes(totals?.out_bytes ?? 0)} total
          </span>
        </div>
        <div className={styles.stat} data-way="in">
          <span className={styles.value}>
            {latest ? formatBitRate(latest.inBps) : '-'}
          </span>
          <span className={styles.label}>
            in · {formatBytes(totals?.in_bytes ?? 0)} total
          </span>
        </div>
        <div className={styles.stat}>
          <span className={styles.value}>
            {formatBytes(
              (totals?.internal_bytes ?? 0) + (totals?.transit_bytes ?? 0)
            )}
          </span>
          <span className={styles.label}>internal and transit</span>
        </div>
      </section>

      <section className={styles.top}>
        <Throughput samples={samples} />
        <Talkers talkers={view?.talkers ?? []} />
      </section>

      <CropFrame
        label="conversations"
        aside={
          <span className={styles.aside}>
            {filtering
              ? `${shown.length.toLocaleString()} of ${flows.length.toLocaleString()}`
              : `${flows.length.toLocaleString()} shown`}
            {totals && totals.flows_shed > 0
              ? ` · ${totals.flows_shed.toLocaleString()} shed`
              : ''}
          </span>
        }
        className={styles.frame}
      >
        <div className={styles.controls}>
          <fieldset className={styles.chips}>
            <legend className={styles.srOnly}>Direction</legend>
            {DIRECTIONS.map((id) => (
              <button
                key={id}
                type="button"
                className={cx(styles.chip, direction === id && styles.chipOn)}
                aria-pressed={direction === id}
                onClick={() => setDirection(id)}
              >
                {id}
              </button>
            ))}
          </fieldset>
          <fieldset className={styles.chips}>
            <legend className={styles.srOnly}>Protocol</legend>
            {PROTOS.map((id) => (
              <button
                key={id}
                type="button"
                className={cx(styles.chip, proto === id && styles.chipOn)}
                aria-pressed={proto === id}
                onClick={() => setProto(id)}
              >
                {id}
              </button>
            ))}
            <button
              type="button"
              className={cx(styles.chip, namedOnly && styles.chipOn)}
              aria-pressed={namedOnly}
              onClick={() => setNamedOnly(!namedOnly)}
            >
              with server name
            </button>
          </fieldset>
          <input
            type="search"
            className={styles.search}
            placeholder="filter address, server name, service, client"
            aria-label="Filter conversations"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <fieldset className={styles.chips}>
            <legend className={styles.srOnly}>Sort</legend>
            {SORTS.map((item) => (
              <button
                key={item.id}
                type="button"
                className={cx(styles.chip, sort === item.id && styles.chipOn)}
                aria-pressed={sort === item.id}
                onClick={() => setSort(item.id)}
              >
                {item.label}
              </button>
            ))}
            <button
              type="button"
              className={styles.chip}
              disabled={shown.length === 0}
              title="Download the conversations listed, as a spreadsheet"
              onClick={() =>
                downloadText(
                  `tlsfp-conversations-${stamp()}.csv`,
                  'text/csv',
                  toCsv(FLOW_HEADERS, flowRows(shown))
                )
              }
            >
              csv
            </button>
          </fieldset>
        </div>

        {flows.length === 0 ? (
          <p className={styles.idle}>no conversations yet</p>
        ) : shown.length === 0 ? (
          <p className={styles.idle}>no conversation matches this filter</p>
        ) : (
          <Conversations flows={shown.slice(0, 200)} total={shown.length} />
        )}
      </CropFrame>
    </div>
  )
}

Component.displayName = 'Traffic'
