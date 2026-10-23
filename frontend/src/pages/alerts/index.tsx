/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { exportHref, useRecentAlerts } from '@/api/hooks'
import {
  type Alert,
  formatClock,
  RULE_VALUES,
  type Rule,
  type Severity,
} from '@/api/types'
import { CropFrame, cx, RuleTag, SeverityTag } from '@/components'
import { ROUTES } from '@/config'
import {
  type AlertFilter,
  countBy,
  matchesFilter,
  RULE_NOTES,
  SEVERITIES,
  toggle,
} from './alert-data'
import styles from './alerts.module.scss'

const PAGE = 1000

function entryKey(alert: Alert, index: number): string {
  return `${alert.ts_nanos}-${alert.rule}-${alert.fp_value ?? ''}-${index}`
}

function Entry({
  alert,
  open,
  onToggle,
}: {
  alert: Alert
  open: boolean
  onToggle: () => void
}): React.ReactElement {
  const note = RULE_NOTES[alert.rule]
  return (
    <li className={styles.entry} data-sev={alert.severity}>
      <button
        type="button"
        className={styles.line}
        aria-expanded={open}
        onClick={onToggle}
      >
        <SeverityTag severity={alert.severity} />
        <RuleTag rule={alert.rule} />
        <span className={styles.title}>{alert.title}</span>
        <span className={styles.ip}>{alert.ip ?? ''}</span>
        <span className={styles.time}>{formatClock(alert.ts_nanos)}</span>
      </button>
      {open && (
        <div className={styles.detail}>
          <p className={styles.text}>{alert.detail}</p>
          <dl className={styles.facts}>
            {alert.ip && (
              <>
                <dt>address</dt>
                <dd>{alert.ip}</dd>
              </>
            )}
            {alert.fp_value && (
              <>
                <dt>{alert.fp_kind ?? 'fingerprint'}</dt>
                <dd>{alert.fp_value}</dd>
              </>
            )}
            {alert.score !== undefined && (
              <>
                <dt>score</dt>
                <dd>{alert.score.toFixed(2)}</dd>
              </>
            )}
          </dl>
          <h4 className={styles.sub}>what this rule means</h4>
          <p className={styles.text}>{note.what}</p>
          <h4 className={styles.sub}>before you act</h4>
          <p className={styles.text}>{note.next}</p>
          {alert.fp_value && (
            <Link
              className={styles.link}
              to={`${ROUTES.SCOPE}?q=${encodeURIComponent(alert.fp_value)}`}
            >
              show this fingerprint in the live stream
            </Link>
          )}
        </div>
      )}
    </li>
  )
}

export function Component(): React.ReactElement {
  const { data, isLoading } = useRecentAlerts(PAGE)
  const alerts = data ?? []
  const [severities, setSeverities] = useState<Set<Severity>>(new Set())
  const [rules, setRules] = useState<Set<Rule>>(new Set())
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<string | null>(null)

  const filter: AlertFilter = { severities, rules, query }
  const shown = useMemo(
    () => alerts.filter((a) => matchesFilter(a, { severities, rules, query })),
    [alerts, severities, rules, query]
  )
  const bySeverity = useMemo(() => countBy(alerts, (a) => a.severity), [alerts])
  const byRule = useMemo(() => countBy(alerts, (a) => a.rule), [alerts])
  const filtering =
    filter.severities.size > 0 || filter.rules.size > 0 || query !== ''

  const aside = (
    <span className={styles.aside}>
      {filtering
        ? `${shown.length.toLocaleString()} of ${alerts.length.toLocaleString()}`
        : `${alerts.length.toLocaleString()} recorded`}
    </span>
  )

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>detections</span>
        <h1 className={styles.title1}>Alerts</h1>
        <p className={styles.sub1}>
          Every alert the detection rules have raised, newest first. Open one to
          see what the rule means and what to check before acting on it.
        </p>
      </section>

      <section className={styles.severities} aria-label="Alerts by severity">
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            type="button"
            className={cx(styles.tile, severities.has(sev) && styles.tileOn)}
            data-sev={sev}
            aria-pressed={severities.has(sev)}
            onClick={() => setSeverities(toggle(severities, sev))}
          >
            <span className={styles.count}>
              {(bySeverity.get(sev) ?? 0).toLocaleString()}
            </span>
            <span className={styles.tileLabel}>{sev}</span>
          </button>
        ))}
      </section>

      <CropFrame label="alerts" aside={aside} className={styles.frame}>
        <div className={styles.controls}>
          <fieldset className={styles.chips}>
            <legend className={styles.srOnly}>Filter by rule</legend>
            {RULE_VALUES.map((rule) => (
              <button
                key={rule}
                type="button"
                className={cx(styles.chip, rules.has(rule) && styles.chipOn)}
                aria-pressed={rules.has(rule)}
                onClick={() => setRules(toggle(rules, rule))}
              >
                {rule} · {byRule.get(rule) ?? 0}
              </button>
            ))}
          </fieldset>
          <input
            type="search"
            className={styles.search}
            placeholder="filter address, fingerprint, text"
            aria-label="Filter alerts"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          {filtering && (
            <button
              type="button"
              className={styles.chip}
              onClick={() => {
                setSeverities(new Set())
                setRules(new Set())
                setQuery('')
              }}
            >
              reset
            </button>
          )}
          <span className={styles.exports}>
            <a className={styles.chip} href={exportHref('json', PAGE)}>
              json
            </a>
            <a className={styles.chip} href={exportHref('csv', PAGE)}>
              csv
            </a>
          </span>
        </div>

        {isLoading ? (
          <p className={styles.idle}>reading the ledger</p>
        ) : alerts.length === 0 ? (
          <p className={styles.idle}>
            no alerts yet. replay a capture or start a live sensor with detection
            on
          </p>
        ) : shown.length === 0 ? (
          <p className={styles.idle}>no alert matches this filter</p>
        ) : (
          <ul className={styles.list}>
            {shown.map((alert, index) => {
              const key = entryKey(alert, index)
              return (
                <Entry
                  key={key}
                  alert={alert}
                  open={open === key}
                  onToggle={() => setOpen(open === key ? null : key)}
                />
              )
            })}
          </ul>
        )}
      </CropFrame>
    </div>
  )
}

Component.displayName = 'Alerts'
