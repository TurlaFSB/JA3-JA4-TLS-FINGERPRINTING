/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useHost, useHosts } from '@/api/hooks'
import type { HostProfile } from '@/api/types'
import { formatClock } from '@/api/types'
import { CropFrame, cx, RuleTag, SeverityTag, VerdictBadge } from '@/components'
import { ROUTES } from '@/config'
import {
  appeared,
  barFor,
  type HostSort,
  laterClients,
  matchesHost,
  sortHosts,
  whenText,
} from './host-data'
import styles from './hosts.module.scss'

const SORTS: { id: HostSort; label: string }[] = [
  { id: 'recent', label: 'recent' },
  { id: 'clients', label: 'most clients' },
  { id: 'alerts', label: 'most alerts' },
]

function Timeline({ profile }: { profile: HostProfile }): React.ReactElement {
  const { summary, clients } = profile
  return (
    <ul
      className={styles.timeline}
      aria-label="When each client fingerprint was seen"
    >
      {clients.map((client) => {
        const bar = barFor(client, summary.first_ts, summary.last_ts)
        return (
          <li key={client.ja4}>
            <span className={styles.who} title={client.ja4}>
              {client.label ?? client.ja4}
            </span>
            <span className={styles.track}>
              <span
                className={styles.bar}
                data-verdict={client.verdict ?? 'unknown'}
                style={{ left: `${bar.left}%`, width: `${bar.width}%` }}
                title={`${whenText(client.first_ts)} to ${whenText(client.last_ts)}`}
              />
            </span>
            <span className={styles.count}>{client.count.toLocaleString()}</span>
          </li>
        )
      })}
      <li className={styles.axis} aria-hidden="true">
        <span />
        <span className={styles.ends}>
          <span>{whenText(summary.first_ts)}</span>
          <span>{whenText(summary.last_ts)}</span>
        </span>
        <span />
      </li>
    </ul>
  )
}

function Profile({ ip }: { ip: string }): React.ReactElement {
  const { data, isLoading, isError } = useHost(ip)
  if (isLoading) return <p className={styles.idle}>loading</p>
  if (isError || !data) {
    return <p className={styles.idle}>nothing was observed from {ip}</p>
  }
  const later = laterClients(data.clients)
  const s = data.summary
  return (
    <div className={styles.profile}>
      <header className={styles.profileHead}>
        <h2 className={styles.address}>{s.ip}</h2>
        {s.verdict && <VerdictBadge verdict={s.verdict} />}
        <span className={styles.meta}>
          {s.observations.toLocaleString()} observations · {s.clients} client
          {s.clients === 1 ? '' : 's'} · {s.servers} server name
          {s.servers === 1 ? '' : 's'} · first {whenText(s.first_ts)} · last{' '}
          {whenText(s.last_ts)}
        </span>
      </header>

      <h3 className={styles.sub}>client fingerprints over time</h3>
      <Timeline profile={data} />

      <h3 className={styles.sub}>changes</h3>
      {later.length === 0 ? (
        <p className={styles.note}>
          One client fingerprint so far: nothing about this host has changed.
        </p>
      ) : (
        <ul className={styles.changes}>
          {later.map((client) => (
            <li key={client.ja4}>
              <span className={styles.tag}>new client</span>
              <span>
                {client.label ?? client.ja4} <i>{appeared(client, s.first_ts)}</i>
              </span>
              <Link
                className={styles.link}
                to={`${ROUTES.SCOPE}?q=${encodeURIComponent(client.ja4)}`}
              >
                stream
              </Link>
            </li>
          ))}
        </ul>
      )}

      <div className={styles.cols}>
        <div>
          <h3 className={styles.sub}>servers it talks to</h3>
          <ul className={styles.list}>
            {data.servers.slice(0, 12).map((server) => (
              <li key={server.value}>
                <span>{server.value}</span>
                <span>{server.count}</span>
              </li>
            ))}
            {data.servers.length === 0 && (
              <li className={styles.note}>none seen</li>
            )}
          </ul>
        </div>
        <div>
          <h3 className={styles.sub}>what it says it is</h3>
          <ul className={styles.list}>
            {data.user_agents.map((agent) => (
              <li key={agent.value}>
                <span title={agent.value}>{agent.value}</span>
                <span>{agent.count}</span>
              </li>
            ))}
            {data.os_claims.map((claim) => (
              <li key={claim.value}>
                <span>OS: {claim.value}</span>
                <span>{claim.count}</span>
              </li>
            ))}
            {data.user_agents.length === 0 && data.os_claims.length === 0 && (
              <li className={styles.note}>no cleartext HTTP seen</li>
            )}
          </ul>
        </div>
      </div>

      <h3 className={styles.sub}>
        alerts about this host ({data.alerts.length})
      </h3>
      <ul className={styles.alerts}>
        {data.alerts.slice(0, 12).map((alert) => (
          <li key={`${alert.ts_nanos}-${alert.rule}-${alert.fp_value ?? ''}`}>
            <SeverityTag severity={alert.severity} />
            <RuleTag rule={alert.rule} />
            <span className={styles.alertTitle}>{alert.title}</span>
            <span className={styles.clock}>{formatClock(alert.ts_nanos)}</span>
          </li>
        ))}
        {data.alerts.length === 0 && <li className={styles.note}>none</li>}
      </ul>
    </div>
  )
}

export function Component(): React.ReactElement {
  const { data, isLoading } = useHosts()
  const [params, setParams] = useSearchParams()
  const selected = params.get('ip')
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<HostSort>('recent')
  const hosts = data ?? []
  const shown = useMemo(
    () =>
      sortHosts(
        hosts.filter((host) => matchesHost(host, query)),
        sort
      ),
    [hosts, query, sort]
  )

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>hosts</span>
        <h1 className={styles.title}>Hosts</h1>
        <p className={styles.sub1}>
          What the sensor has learned about each address over time: which client
          fingerprints it runs, when each first appeared, which servers it talks
          to and which alerts it raised. A host that starts presenting a new
          client is the thing to look at. Addresses behind a NAT gateway appear as
          one host.
        </p>
      </section>

      <div className={styles.layout}>
        <CropFrame
          label="addresses"
          aside={
            <span className={styles.aside}>
              {hosts.length.toLocaleString()} seen
            </span>
          }
          className={styles.listFrame}
        >
          <div className={styles.controls}>
            <input
              type="search"
              className={styles.search}
              placeholder="filter address or client"
              aria-label="Filter hosts"
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
            </fieldset>
          </div>
          {isLoading ? (
            <p className={styles.idle}>loading</p>
          ) : hosts.length === 0 ? (
            <p className={styles.idle}>
              no hosts yet. Hosts are recorded while detection runs: start the
              server with <code>--live</code> or <code>--replay</code>, or run a
              capture with <code>--detect</code>.
            </p>
          ) : (
            <div className={styles.table}>
              <div className={cx(styles.row, styles.head)} aria-hidden="true">
                <span>address</span>
                <span className={styles.num}>clients</span>
                <span className={styles.num}>servers</span>
                <span className={styles.num}>alerts</span>
              </div>
              {shown.map((host) => (
                <button
                  key={host.ip}
                  type="button"
                  className={styles.row}
                  data-selected={selected === host.ip}
                  aria-pressed={selected === host.ip}
                  onClick={() => setParams({ ip: host.ip })}
                >
                  <span className={styles.ip}>
                    {host.ip}
                    {host.top_label && <i>{host.top_label}</i>}
                  </span>
                  <span className={styles.num}>{host.clients}</span>
                  <span className={styles.num}>{host.servers}</span>
                  <span className={styles.num}>{host.alerts}</span>
                </button>
              ))}
            </div>
          )}
        </CropFrame>

        <CropFrame label="profile" className={styles.profileFrame}>
          {selected ? (
            <Profile ip={selected} />
          ) : (
            <p className={styles.idle}>choose an address to see its history</p>
          )}
        </CropFrame>
      </div>
    </div>
  )
}

Component.displayName = 'Hosts'
