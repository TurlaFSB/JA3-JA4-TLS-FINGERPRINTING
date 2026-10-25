/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useDns } from '@/api/hooks'
import type { DnsName } from '@/api/types'
import { CropFrame } from '@/components'
import { ROUTES } from '@/config'
import { downloadText, stamp, toCsv } from '@/core/lib/export'
import { useClock } from '@/core/lib/use-clock'
import styles from './dns.module.scss'
import {
  type DnsFilter,
  failureRate,
  matchesName,
  percent,
  result,
} from './dns-data'

const SHOWN = 100

function NameTable({
  names,
  empty,
}: {
  names: DnsName[]
  empty: string
}): React.ReactElement {
  return (
    <div className={styles.table}>
      <div className={styles.head} data-cols="names">
        <span>name</span>
        <span className={styles.num}>asked</span>
        <span className={styles.num}>hosts</span>
        <span className={styles.num}>no such name</span>
        <span>resolved to</span>
      </div>
      {names.length === 0 && <p className={styles.empty}>{empty}</p>}
      {names.slice(0, SHOWN).map((row) => (
        <div key={row.name} className={styles.row} data-cols="names">
          <span className={styles.name} title={row.name}>
            {row.name}
            {row.random_looking && (
              <span
                className={styles.flag}
                title="The first label is long and random-looking. Content networks and trackers also generate such names, so this is a hint, not a verdict."
              >
                random-looking
              </span>
            )}
          </span>
          <span className={styles.num}>{row.queries}</span>
          <span className={styles.num}>{row.clients}</span>
          <span
            className={styles.num}
            data-bad={row.nxdomain + row.failures > 0 || undefined}
          >
            {row.nxdomain + row.failures}
          </span>
          <span className={styles.addrs} title={row.addresses.join(', ')}>
            {row.addresses.join(', ')}
          </span>
        </div>
      ))}
    </div>
  )
}

export function Component(): React.ReactElement {
  const { data, isError } = useDns()
  const clock = useClock()
  const [query, setQuery] = useState('')
  const [randomOnly, setRandomOnly] = useState(false)
  const [failingOnly, setFailingOnly] = useState(false)
  const filter = useMemo<DnsFilter>(
    () => ({ query, randomOnly, failingOnly }),
    [query, randomOnly, failingOnly]
  )

  const names = useMemo(
    () => (data?.top_names ?? []).filter((n) => matchesName(n, filter)),
    [data, filter]
  )
  const totals = data?.totals
  const silent = !!data && data.totals.queries + data.totals.responses === 0

  const exportCsv = (): void => {
    if (!data) return
    downloadText(
      `tlsfp-dns-${stamp()}.csv`,
      'text/csv',
      toCsv(
        [
          'name',
          'asked',
          'hosts',
          'nxdomain',
          'failures',
          'resolved_to',
          'random_looking',
        ],
        data.top_names.map((n) => [
          n.name,
          n.queries,
          n.clients,
          n.nxdomain,
          n.failures,
          n.addresses.join(' '),
          n.random_looking,
        ])
      )
    )
  }

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>dns</span>
        <h1 className={styles.title}>DNS</h1>
        <p className={styles.sub}>
          The names machines ask for before they connect, read from plain DNS on
          UDP port 53. It names servers whose handshake hides its name, and shows
          lookups that fail. DNS over HTTPS or TLS is encrypted and does not
          appear here.
        </p>
      </section>

      {isError && <p className={styles.notice}>The server did not answer.</p>}
      {silent && (
        <p className={styles.notice}>
          No DNS has been seen yet. Plain DNS appears when the capture includes
          UDP port 53 (the default live filter does), and not at all if this
          machine resolves names over HTTPS or TLS. Try the{' '}
          <Link to={ROUTES.TRAFFIC}>Traffic</Link> page to check what is crossing
          the sensor.
        </p>
      )}

      <section className={styles.stats} aria-label="DNS totals">
        <div className={styles.stat}>
          <span className={styles.value}>
            {(totals?.queries ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>queries</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.value}>
            {(totals?.responses ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>responses</span>
        </div>
        <div
          className={styles.stat}
          data-bad={(totals?.nxdomain ?? 0) > 0 || undefined}
        >
          <span className={styles.value}>
            {(totals?.nxdomain ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>
            no such name · {totals ? percent(failureRate(totals)) : '0%'} of
            responses
          </span>
        </div>
        <div className={styles.stat}>
          <span className={styles.value}>
            {(totals?.failures ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>server failures</span>
        </div>
      </section>

      <div className={styles.controls}>
        <input
          className={styles.search}
          placeholder="filter by name or address"
          aria-label="Filter DNS names"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <button
          type="button"
          className={styles.chip}
          aria-pressed={failingOnly}
          data-on={failingOnly || undefined}
          onClick={() => setFailingOnly(!failingOnly)}
        >
          failing only
        </button>
        <button
          type="button"
          className={styles.chip}
          aria-pressed={randomOnly}
          data-on={randomOnly || undefined}
          onClick={() => setRandomOnly(!randomOnly)}
        >
          random-looking only
        </button>
        <button type="button" className={styles.chip} onClick={exportCsv}>
          export csv
        </button>
      </div>

      <div className={styles.grid}>
        <CropFrame
          label="most asked names"
          aside={`${names.length} shown`}
          className={styles.wide}
        >
          <NameTable names={names} empty="No name matches." />
        </CropFrame>

        <CropFrame label="busiest hosts">
          <div className={styles.table}>
            <div className={styles.head} data-cols="clients">
              <span>host</span>
              <span className={styles.num}>queries</span>
              <span className={styles.num}>no such name</span>
            </div>
            {(data?.top_clients ?? []).length === 0 && (
              <p className={styles.empty}>No lookups yet.</p>
            )}
            {(data?.top_clients ?? []).map((row) => (
              <div key={row.client} className={styles.row} data-cols="clients">
                <Link
                  className={styles.link}
                  to={`${ROUTES.HOSTS}?ip=${encodeURIComponent(row.client)}`}
                >
                  {row.client}
                </Link>
                <span className={styles.num}>{row.queries}</span>
                <span
                  className={styles.num}
                  data-bad={row.nxdomain > 0 || undefined}
                >
                  {row.nxdomain}
                </span>
              </div>
            ))}
          </div>
        </CropFrame>
      </div>

      <CropFrame
        label="names that did not resolve"
        aside="a long list is worth a look: stale configuration, typos, or software probing for names"
      >
        <NameTable
          names={(data?.top_failing ?? []).filter((n) => matchesName(n, filter))}
          empty="Every answered lookup resolved."
        />
      </CropFrame>

      <CropFrame
        label="recent lookups"
        aside={`last ${data?.recent.length ?? 0}`}
      >
        <div className={styles.table}>
          <div className={styles.head} data-cols="recent">
            <span>time</span>
            <span>host</span>
            <span>name</span>
            <span>type</span>
            <span>result</span>
          </div>
          {(data?.recent ?? [])
            .filter((row) =>
              matchesName(
                {
                  name: row.name,
                  queries: 0,
                  answered: 0,
                  nxdomain: row.rcode === 'NXDOMAIN' ? 1 : 0,
                  failures: 0,
                  clients: 0,
                  last_ts: 0,
                  addresses: row.answers,
                  random_looking: false,
                },
                { ...filter, randomOnly: false }
              )
            )
            .slice(0, SHOWN)
            .map((row, index) => (
              <div
                // A name can repeat at the same instant; position disambiguates.
                key={`${row.ts_nanos}-${row.client}-${row.name}-${index}`}
                className={styles.row}
                data-cols="recent"
              >
                <span className={styles.time}>{clock(row.ts_nanos)}</span>
                <span>{row.client}</span>
                <span className={styles.name} title={row.name}>
                  {row.name}
                </span>
                <span>{row.qtype}</span>
                <span
                  className={styles.addrs}
                  data-bad={
                    (row.rcode !== '' && row.rcode !== 'NOERROR') || undefined
                  }
                >
                  {result(row.rcode, row.answers)}
                </span>
              </div>
            ))}
        </div>
      </CropFrame>
    </div>
  )
}
