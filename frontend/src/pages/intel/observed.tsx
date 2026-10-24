/**
 * © Pranav Verma | 2026
 * observed.tsx
 */

import { useMemo, useState } from 'react'
import { useObserved } from '@/api/hooks'
import type { Coverage, Knowledge, ObservedClient } from '@/api/types'
import { formatClock } from '@/api/types'
import { CropFrame, cx } from '@/components'
import styles from './observed.module.scss'

type View = 'all' | 'unknown' | 'known'

const KNOWLEDGE_TEXT: Record<Knowledge, string> = {
  exact: 'known',
  partial: 'similar',
  unknown: 'unknown',
}

const KNOWLEDGE_NOTE: Record<Knowledge, string> = {
  exact: 'An identical fingerprint is in the feed or your labels.',
  partial:
    'Only a similar fingerprint is in the feed: the same cipher list with a different extension set. A hint, not an identification.',
  unknown: 'Nothing in the feed resembles it.',
}

const FAMILY_NAME: Record<string, string> = {
  chromium: 'Chromium (Chrome, Edge, Brave, Opera)',
  firefox: 'Firefox',
  safari_like: 'Safari-like',
  open_ssl: 'OpenSSL client',
  library: 'script or library',
  unknown: 'unrecognised',
}

function familyName(family: string): string {
  return FAMILY_NAME[family] ?? family.replace(/_/g, ' ')
}

// What to call a fingerprint in the table. Only an exact match is a name. A
// similar fingerprint is a hint and is shown as one, after what the shape of
// the handshake itself says.
function nameOf(client: ObservedClient): string {
  if (client.knowledge === 'exact' && client.label) return client.label
  if (client.guess && client.guess.family !== 'unknown') {
    return `looks like ${familyName(client.guess.family)}`
  }
  if (client.knowledge === 'partial' && client.label) {
    return `similar to ${client.label}`
  }
  return ''
}

function percent(part: number, whole: number): number {
  return whole === 0 ? 0 : Math.round((part / whole) * 100)
}

function CoverageStrip({ coverage }: { coverage: Coverage }): React.ReactElement {
  const named = percent(coverage.exact_connections, coverage.connections)
  return (
    <div className={styles.coverage}>
      <div className={styles.big}>
        <span className={styles.bigNumber}>{named}%</span>
        <span className={styles.bigLabel}>
          of {coverage.connections.toLocaleString()} connections come from a
          fingerprint the feed names exactly
        </span>
      </div>
      <dl className={styles.counts}>
        <div>
          <dt>fingerprints seen</dt>
          <dd>{coverage.fingerprints.toLocaleString()}</dd>
        </div>
        <div>
          <dt>known</dt>
          <dd className={styles.known}>{coverage.exact.toLocaleString()}</dd>
        </div>
        <div>
          <dt>similar only</dt>
          <dd>{coverage.partial.toLocaleString()}</dd>
        </div>
        <div>
          <dt>unknown</dt>
          <dd className={styles.unknown}>{coverage.unknown.toLocaleString()}</dd>
        </div>
      </dl>
    </div>
  )
}

function CopyCommand({ command }: { command: string }): React.ReactElement {
  const [copied, setCopied] = useState(false)
  return (
    <div className={styles.command}>
      <code>{command}</code>
      <button
        type="button"
        className={styles.copy}
        onClick={() => {
          navigator.clipboard
            ?.writeText(command)
            .then(() => {
              setCopied(true)
              setTimeout(() => setCopied(false), 1200)
            })
            .catch(() => undefined)
        }}
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </div>
  )
}

function Row({
  client,
  open,
  onToggle,
}: {
  client: ObservedClient
  open: boolean
  onToggle: () => void
}): React.ReactElement {
  const guess = client.guess
  const name = nameOf(client)
  return (
    <div className={styles.item}>
      <button
        type="button"
        className={styles.row}
        aria-expanded={open}
        onClick={onToggle}
      >
        <span
          className={styles.badge}
          data-knowledge={client.knowledge}
          title={KNOWLEDGE_NOTE[client.knowledge]}
        >
          {KNOWLEDGE_TEXT[client.knowledge]}
        </span>
        <span className={styles.ja4} title={client.ja4}>
          {client.ja4}
        </span>
        <span
          className={cx(
            styles.name,
            client.knowledge !== 'exact' && styles.guessed
          )}
        >
          {name}
        </span>
        <span className={styles.sites}>{client.sites.join(', ')}</span>
        <span className={styles.num}>{client.connections.toLocaleString()}</span>
        <span className={styles.num}>{client.hosts.toLocaleString()}</span>
        <span className={styles.when}>
          {formatClock(client.last_ts).slice(0, 8)}
        </span>
      </button>
      {open && (
        <div className={styles.detail}>
          <dl className={styles.facts}>
            <dt>fingerprint</dt>
            <dd className={styles.mono}>{client.ja4}</dd>
            <dt>first seen</dt>
            <dd>{new Date(client.first_ts / 1e6).toLocaleString()}</dd>
            <dt>last seen</dt>
            <dd>{new Date(client.last_ts / 1e6).toLocaleString()}</dd>
            {client.source && (
              <>
                <dt>
                  {client.knowledge === 'exact' ? 'named by' : 'similar to'}
                </dt>
                <dd>
                  {client.label} ({client.source})
                  {client.knowledge === 'partial' &&
                    '. Same cipher list, different extensions: a hint, not an identification.'}
                </dd>
              </>
            )}
            {guess && (
              <>
                <dt>shape suggests</dt>
                <dd>
                  {familyName(guess.family)} ({guess.confidence} confidence).{' '}
                  {guess.reasons.join('; ')}
                  {guess.caveat && (
                    <span className={styles.caveat}> {guess.caveat}</span>
                  )}
                </dd>
              </>
            )}
          </dl>
          {client.knowledge !== 'exact' && (
            <>
              <p className={styles.help}>
                Know what this is? Name it so the dashboard shows your label from
                now on. It is stored in your own feed ("local labels") and never
                overwrites a public one.
              </p>
              <CopyCommand
                command={`tlsfp intel label ja4 ${client.ja4} --label "your name for it"`}
              />
            </>
          )}
        </div>
      )}
    </div>
  )
}

export function Observed(): React.ReactElement {
  const { data, isLoading, isError } = useObserved()
  const [view, setView] = useState<View>('unknown')
  const [open, setOpen] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return (data?.clients ?? []).filter((client) => {
      if (view === 'unknown' && client.knowledge === 'exact') return false
      if (view === 'known' && client.knowledge !== 'exact') return false
      return (
        needle === '' ||
        `${client.ja4} ${client.label ?? ''} ${client.sites.join(' ')}`
          .toLowerCase()
          .includes(needle)
      )
    })
  }, [data, view, query])

  return (
    <CropFrame label="seen on this sensor" className={styles.frame}>
      {isError ? (
        <p className={styles.idle}>The server did not answer.</p>
      ) : isLoading || !data ? (
        <p className={styles.idle}>loading</p>
      ) : data.coverage.fingerprints === 0 ? (
        <p className={styles.idle}>
          Nothing has been recorded yet. Client fingerprints appear here as the
          sensor sees handshakes (start the server with <code>--live</code> or{' '}
          <code>--replay</code>).
        </p>
      ) : (
        <>
          <CoverageStrip coverage={data.coverage} />
          <div className={styles.controls}>
            <fieldset className={styles.chips}>
              <legend className={styles.srOnly}>Show</legend>
              {(
                [
                  ['unknown', 'needs a name'],
                  ['known', 'known'],
                  ['all', 'all'],
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
            <input
              type="search"
              className={styles.search}
              placeholder="filter fingerprint, name or site"
              aria-label="Filter observed fingerprints"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className={styles.table}>
            <div className={cx(styles.row, styles.head)} aria-hidden="true">
              <span>feed</span>
              <span>fingerprint</span>
              <span>what it is</span>
              <span>sites</span>
              <span className={styles.num}>conn.</span>
              <span className={styles.num}>hosts</span>
              <span>last</span>
            </div>
            {rows.length === 0 ? (
              <p className={styles.idle}>
                {view === 'unknown'
                  ? 'Every fingerprint seen so far is known to the feed.'
                  : 'Nothing matches.'}
              </p>
            ) : (
              rows.map((client) => (
                <Row
                  key={client.ja4}
                  client={client}
                  open={open === client.ja4}
                  onToggle={() =>
                    setOpen(open === client.ja4 ? null : client.ja4)
                  }
                />
              ))
            )}
          </div>
        </>
      )}
    </CropFrame>
  )
}
