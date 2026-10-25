/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useDns, useMeta, useTraffic } from '@/api/hooks'
import type { DnsLookup, DnsName, DnsView, Finding } from '@/api/types'
import { CropFrame } from '@/components'
import { ROUTES } from '@/config'
import { downloadText, stamp, toCsv } from '@/core/lib/export'
import { formatBytes } from '@/core/lib/format'
import { useClock } from '@/core/lib/use-clock'
import { protocolWords, serverEndpoint } from '@/pages/traffic/traffic-data'
import styles from './dns.module.scss'
import {
  type DnsFilter,
  displayName,
  failureRate,
  flowsFor,
  isFailure,
  KIND_WORDS,
  latencyText,
  lookupsFor,
  matchesName,
  meaning,
  mergeLookups,
  NAME_HEADERS,
  nameRows,
  percent,
  qtypeWords,
  resultWords,
  summarize,
} from './dns-data'

const SHOWN = 100

function NameDetail({
  row,
  view,
}: {
  row: DnsName
  view: DnsView
}): React.ReactElement {
  const clock = useClock()
  const { view: traffic } = useTraffic()
  const lookups = lookupsFor(row.name, view.recent).slice(0, 12)
  const flows = flowsFor(row, traffic?.flows ?? []).slice(0, 12)
  return (
    <div className={styles.detail}>
      <p className={styles.sentence}>{meaning(row)}</p>
      <div className={styles.cols}>
        <dl className={styles.facts}>
          <dt>kind</dt>
          <dd>{KIND_WORDS[row.kind]}</dd>
          <dt>asked for</dt>
          <dd>
            {row.qtypes.map((t) => `${t} (${qtypeWords(t)})`).join(', ') || 'n/a'}
          </dd>
          <dt>asked of</dt>
          <dd>{row.resolvers.join(', ') || 'n/a'}</dd>
          <dt>first seen</dt>
          <dd>{clock(row.first_ts)}</dd>
          <dt>last seen</dt>
          <dd>{clock(row.last_ts)}</dd>
          {row.latency_ms !== null && (
            <>
              <dt>answer time</dt>
              <dd>about {latencyText(row.latency_ms)}</dd>
            </>
          )}
          {row.ttl !== null && (
            <>
              <dt>cache time</dt>
              <dd>
                {row.ttl} s: how long the answer may be reused before asking again
              </dd>
            </>
          )}
          {row.addresses.length > 0 && (
            <>
              <dt>{row.kind === 'reverse' ? 'name' : 'resolved to'}</dt>
              <dd>{row.addresses.join(', ')}</dd>
            </>
          )}
        </dl>

        <div>
          <h4 className={styles.heading}>lookups of this name</h4>
          <ul className={styles.mini}>
            {lookups.length === 0 && <li>none in the recent window</li>}
            {lookups.map((l, i) => (
              <li key={`${l.ts_nanos}-${l.client}-${l.qtype}-${l.rcode}-${i}`}>
                <span className={styles.time}>{clock(l.ts_nanos)}</span>{' '}
                {l.client} → {l.resolver} · {l.qtype} · {resultWords(l)}
                {l.latency_ms !== null && ` · ${latencyText(l.latency_ms)}`}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h4 className={styles.heading}>connections that followed</h4>
          <ul className={styles.mini}>
            {flows.length === 0 && (
              <li>
                none seen. The name may not have been connected to, or it resolved
                to an address nobody has talked to yet.
              </li>
            )}
            {flows.map((f) => (
              <li key={`${f.proto}-${f.client}-${f.server}`}>
                {f.client} → {serverEndpoint(f).primary} ({f.server}) ·{' '}
                {protocolWords(f)} · {formatBytes(f.bytes_up + f.bytes_down)}
              </li>
            ))}
          </ul>
          {flows.length > 0 && (
            <Link
              className={styles.link}
              to={`${ROUTES.TRAFFIC}?q=${encodeURIComponent(row.name)}`}
            >
              open in Traffic
            </Link>
          )}
        </div>
      </div>
    </div>
  )
}

function NameTable({
  names,
  view,
  empty,
}: {
  names: DnsName[]
  view: DnsView
  empty: string
}): React.ReactElement {
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div className={styles.table}>
      <div className={styles.head} data-cols="names">
        <span>name</span>
        <span className={styles.num}>asked</span>
        <span className={styles.num}>hosts</span>
        <span className={styles.num}>no such name</span>
        <span>answer</span>
        <span>asked of</span>
      </div>
      {names.length === 0 && <p className={styles.empty}>{empty}</p>}
      {names.slice(0, SHOWN).map((row) => {
        const expanded = open === row.name
        return (
          <div key={row.name} className={styles.item}>
            <button
              type="button"
              className={styles.row}
              data-cols="names"
              aria-expanded={expanded}
              onClick={() => setOpen(expanded ? null : row.name)}
            >
              <span className={styles.name} title={row.name}>
                <span className={styles.kind} data-kind={row.kind}>
                  {KIND_WORDS[row.kind]}
                </span>
                {displayName(row)}
                {row.blocked && <span className={styles.flag}>blocked</span>}
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
              <span className={styles.addrs} title={row.resolvers.join(', ')}>
                {row.resolvers.join(', ')}
              </span>
            </button>
            {expanded && <NameDetail row={row} view={view} />}
          </div>
        )
      })}
    </div>
  )
}

function Story({
  lines,
  since,
  silent,
}: {
  lines: string[]
  since: number
  silent: boolean
}): React.ReactElement | null {
  const clock = useClock()
  if (lines.length === 0 && !silent) return null
  return (
    <section className={styles.story} aria-label="What is happening">
      <h2 className={styles.storyTitle}>what is happening</h2>
      {silent ? (
        <p className={styles.sentenceLoose}>
          Nothing yet. No plain DNS has crossed the sensor. That happens when the
          capture does not include UDP port 53 (the default live filter does),
          when nothing has looked up a name since the sensor started, or when this
          computer resolves names over HTTPS or TLS (a browser setting often
          called "secure DNS"), which is encrypted and invisible here. Open a new
          website and this page fills in within seconds if the lookup is plain
          DNS. The <Link to={ROUTES.TRAFFIC}>Traffic</Link> page shows what is
          crossing the sensor.
        </p>
      ) : (
        <ul>
          {lines.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
      {since > 0 && (
        <p className={styles.since}>
          since {clock(since)}; kept in memory, so a restart clears it.
        </p>
      )}
    </section>
  )
}

function FindingsPanel({
  findings,
  silent,
}: {
  findings: Finding[]
  silent: boolean
}): React.ReactElement | null {
  if (silent) return null
  return (
    <CropFrame
      label="worth a look"
      aside="patterns in the DNS traffic, with what else could explain them"
    >
      {findings.length === 0 ? (
        <p className={styles.empty}>
          Nothing unusual in what has been heard. Checked for: a host with many
          "no such name" answers, many random-looking subdomains under one domain,
          very long names, lookups at a steady rhythm, names that keep changing
          address, and blocked names.
        </p>
      ) : (
        <ul className={styles.findings}>
          {findings.map((finding) => (
            <li
              key={finding.id}
              className={styles.finding}
              data-severity={finding.severity}
            >
              <span className={styles.severity}>
                {finding.severity === 'notice' ? 'worth a look' : 'good to know'}
              </span>
              <h3 className={styles.findingTitle}>{finding.title}</h3>
              <p className={styles.findingText}>{finding.detail}</p>
              <ul className={styles.evidence}>
                {finding.evidence.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
              <p className={styles.innocent}>Could also be: {finding.innocent}</p>
            </li>
          ))}
        </ul>
      )}
    </CropFrame>
  )
}

function RecentLookups({
  lookups,
  filter,
}: {
  lookups: DnsLookup[]
  filter: DnsFilter
}): React.ReactElement {
  const clock = useClock()
  const merged = mergeLookups(lookups)
  return (
    <CropFrame
      label="recent lookups"
      aside={`newest first · ${merged.length} questions`}
    >
      <div className={styles.table}>
        <div className={styles.head} data-cols="recent">
          <span>time</span>
          <span>from → asked of</span>
          <span>name</span>
          <span>asked for</span>
          <span>result</span>
          <span className={styles.num}>took</span>
        </div>
        {merged
          .filter((row) =>
            matchesName(
              {
                name: row.name,
                kind: 'internet',
                reverse_of: row.reverse_of,
                queries: 0,
                answered: 0,
                nxdomain: row.rcode === 'NXDOMAIN' ? 1 : 0,
                failures: 0,
                clients: 0,
                first_ts: 0,
                last_ts: 0,
                qtypes: [],
                resolvers: [],
                addresses: row.answers.map((a) => a.data),
                latency_ms: null,
                ttl: null,
                blocked: false,
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
              <span
                className={styles.addrs}
                title={`${row.client} asked ${row.resolver}`}
              >
                {row.client} → {row.resolver}
              </span>
              <span className={styles.name} title={row.name}>
                {displayName(row)}
              </span>
              <span title={qtypeWords(row.qtype)}>
                {row.qtype}{' '}
                <span className={styles.dim}>{qtypeWords(row.qtype)}</span>
              </span>
              <span
                className={styles.addrs}
                data-bad={isFailure(row) || undefined}
                title={resultWords(row)}
              >
                {resultWords(row)}
              </span>
              <span className={styles.num}>{latencyText(row.latency_ms)}</span>
            </div>
          ))}
      </div>
    </CropFrame>
  )
}

function SidePanels({ data }: { data: DnsView }): React.ReactElement {
  return (
    <div className={styles.side}>
      <CropFrame label="dns servers">
        <div className={styles.table}>
          <div className={styles.head} data-cols="servers">
            <span>server</span>
            <span className={styles.num}>asked</span>
            <span className={styles.num}>hosts</span>
            <span className={styles.num}>answers in</span>
          </div>
          {data.resolvers.length === 0 && (
            <p className={styles.empty}>None seen.</p>
          )}
          {data.resolvers.map((r) => (
            <div key={r.resolver} className={styles.row} data-cols="servers">
              <span>{r.resolver}</span>
              <span className={styles.num}>{r.queries}</span>
              <span className={styles.num}>{r.clients}</span>
              <span className={styles.num}>{latencyText(r.latency_ms)}</span>
            </div>
          ))}
        </div>
      </CropFrame>

      <CropFrame label="busiest hosts">
        <div className={styles.table}>
          <div className={styles.head} data-cols="clients">
            <span>host</span>
            <span className={styles.num}>asked</span>
            <span className={styles.num}>no such</span>
          </div>
          {data.top_clients.length === 0 && (
            <p className={styles.empty}>No lookups yet.</p>
          )}
          {data.top_clients.map((row) => (
            <div key={row.client} className={styles.row} data-cols="clients">
              <span className={styles.stack}>
                <Link
                  className={styles.link}
                  to={`${ROUTES.HOSTS}?ip=${encodeURIComponent(row.client)}`}
                >
                  {row.client}
                </Link>
                <span className={styles.sub2}>
                  via {row.resolvers.join(', ')}
                </span>
              </span>
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
  )
}

export function Component(): React.ReactElement {
  const { data, isError } = useDns()
  const { data: meta } = useMeta()
  const [params] = useSearchParams()
  const [query, setQuery] = useState(params.get('q') ?? '')
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
  const failing = useMemo(
    () => (data?.top_failing ?? []).filter((n) => matchesName(n, filter)),
    [data, filter]
  )
  const totals = data?.totals
  const silent = !!data && data.totals.queries + data.totals.responses === 0
  const story = data
    ? summarize(data, meta?.source.kind === 'live' ? meta.hostname : null)
    : []

  const exportCsv = (): void => {
    if (!data) return
    downloadText(
      `tlsfp-dns-${stamp()}.csv`,
      'text/csv',
      toCsv(NAME_HEADERS, nameRows(data.top_names))
    )
  }

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>dns</span>
        <h1 className={styles.title}>DNS</h1>
        <p className={styles.sub}>
          DNS is how a computer turns a name into an address before it connects.
          This page shows those questions as they cross the sensor: who asked,
          which DNS server they asked, what name, and what came back. It reads
          plain DNS on UDP port 53; DNS over HTTPS or TLS is encrypted and does
          not appear.
        </p>
      </section>

      {isError && <p className={styles.notice}>The server did not answer.</p>}

      <Story lines={story} since={totals?.since_ts ?? 0} silent={silent} />

      <section className={styles.stats} aria-label="DNS totals">
        <div className={styles.stat}>
          <span className={styles.value}>
            {(totals?.queries ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>questions asked</span>
        </div>
        <div className={styles.stat}>
          <span className={styles.value}>
            {(totals?.responses ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>answers seen</span>
        </div>
        <div
          className={styles.stat}
          data-bad={(totals?.nxdomain ?? 0) > 0 || undefined}
        >
          <span className={styles.value}>
            {(totals?.nxdomain ?? 0).toLocaleString()}
          </span>
          <span className={styles.label}>
            "no such name" · {totals ? percent(failureRate(totals)) : '0%'} of
            answers
          </span>
        </div>
        <div className={styles.stat}>
          <span className={styles.value}>{data?.resolvers.length ?? 0}</span>
          <span className={styles.label}>DNS servers asked</span>
        </div>
      </section>

      <FindingsPanel findings={data?.findings ?? []} silent={silent || !data} />

      <details className={styles.help}>
        <summary>how to read this page</summary>
        <ul>
          <li>
            <b>asked</b>: how many times the name was looked up. <b>hosts</b>: how
            many different machines asked.
          </li>
          <li>
            <b>no such name</b>: the DNS server replied that the name does not
            exist. A few are normal; many for one name point at a typo or a stale
            setting.
          </li>
          <li>
            <b>reverse lookup</b>: asking which name belongs to an address (shown
            here as the address). Operating systems and tools do this to display
            readable names.
          </li>
          <li>
            <b>local name</b>: a name that only means something inside one network
            (<code>.local</code>, <code>.lan</code>, a single word).
          </li>
          <li>
            <b>answer</b> is what the name resolved to. <b>asked of</b> is the DNS
            server that was asked. Click any row for the full picture, including
            the connections that followed.
          </li>
        </ul>
      </details>

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
          label="names asked for"
          aside={`${names.length} shown · click a row for details`}
          className={styles.wide}
        >
          {data ? (
            <NameTable names={names} view={data} empty="No name matches." />
          ) : null}
        </CropFrame>

        {data && <SidePanels data={data} />}
      </div>

      <CropFrame
        label="names that did not resolve"
        aside="a long list is worth a look: stale configuration, typos, or software probing for names"
      >
        {data ? (
          <NameTable
            names={failing}
            view={data}
            empty="Every answered lookup resolved."
          />
        ) : null}
      </CropFrame>

      {data && <RecentLookups lookups={data.recent} filter={filter} />}
    </div>
  )
}
