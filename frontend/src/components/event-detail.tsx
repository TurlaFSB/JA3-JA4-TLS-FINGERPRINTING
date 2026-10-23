/**
 * ©AngelaMos | 2026
 * event-detail.tsx
 */

import { useState } from 'react'
import {
  type Alert,
  decodeJa4,
  formatClock,
  type MatchReport,
  type StreamEvent,
  splitAddr,
} from '@/api/types'
import { SeverityTag, VerdictBadge } from './atoms'
import styles from './event-detail.module.scss'

interface Field {
  label: string
  value: string
}

const KIND_TITLE: Record<StreamEvent['kind'], string> = {
  client_hello: 'client hello',
  server_hello: 'server hello',
  certificate: 'certificate',
  http_request: 'http request',
  tcp_syn: 'tcp syn',
  tcp_syn_ack: 'tcp syn-ack',
}

function fieldsOf(event: StreamEvent): Field[] {
  switch (event.kind) {
    case 'client_hello':
      return [
        { label: 'ja4', value: event.ja4.hash },
        { label: 'ja4 raw', value: event.ja4.raw },
        { label: 'ja3', value: event.ja3 },
        { label: 'ja3 raw', value: event.ja3_raw },
        ...(event.sni ? [{ label: 'sni', value: event.sni }] : []),
        ...(event.alpn ? [{ label: 'alpn', value: event.alpn }] : []),
      ]
    case 'server_hello':
      return [
        { label: 'ja4s', value: event.ja4s.hash },
        { label: 'ja4s raw', value: event.ja4s.raw },
        { label: 'ja3s', value: event.ja3s },
        { label: 'ja3s raw', value: event.ja3s_raw },
      ]
    case 'certificate':
      return [{ label: 'ja4x', value: event.ja4x }]
    case 'http_request':
      return [
        { label: 'ja4h', value: event.ja4h.hash },
        { label: 'ja4h raw', value: event.ja4h.raw },
        { label: 'method', value: event.method },
        ...(event.host ? [{ label: 'host', value: event.host }] : []),
        ...(event.user_agent
          ? [{ label: 'user-agent', value: event.user_agent }]
          : []),
      ]
    case 'tcp_syn':
      return [{ label: 'ja4t', value: event.ja4t }]
    case 'tcp_syn_ack':
      return [{ label: 'ja4ts', value: event.ja4ts }]
  }
}

function CopyButton({ value }: { value: string }): React.ReactElement {
  const [copied, setCopied] = useState(false)
  const copy = (): void => {
    navigator.clipboard
      ?.writeText(value)
      .then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      })
      .catch(() => undefined)
  }
  return (
    <button type="button" className={styles.copy} onClick={copy}>
      {copied ? 'copied' : 'copy'}
    </button>
  )
}

export function EventDetail({
  event,
  intel,
  alerts,
  onClose,
}: {
  event: StreamEvent
  intel?: MatchReport[]
  alerts?: Alert[]
  onClose: () => void
}): React.ReactElement {
  const src = splitAddr(event.src)
  const dst = splitAddr(event.dst)
  const fields = fieldsOf(event)
  const anatomy = event.kind === 'client_hello' ? decodeJa4(event.ja4.hash) : null

  return (
    <aside className={styles.panel} aria-label="Handshake detail">
      <header className={styles.head}>
        <div className={styles.headText}>
          <span className={styles.kind}>{KIND_TITLE[event.kind]}</span>
          <span className={styles.time}>{formatClock(event.ts_nanos)}</span>
        </div>
        <button
          type="button"
          className={styles.close}
          onClick={onClose}
          aria-label="Close detail"
        >
          close
        </button>
      </header>

      <div className={styles.route}>
        <span>
          {src.host}
          <i>:{src.port}</i>
        </span>
        <span className={styles.arrow}>-&gt;</span>
        <span>
          {dst.host}
          <i>:{dst.port}</i>
        </span>
      </div>

      <section className={styles.block}>
        <h3 className={styles.title}>fingerprints</h3>
        <dl className={styles.fields}>
          {fields.map((field) => (
            <div key={field.label} className={styles.field}>
              <dt>{field.label}</dt>
              <dd>
                <span className={styles.value}>{field.value}</span>
                <CopyButton value={field.value} />
              </dd>
            </div>
          ))}
        </dl>
      </section>

      {anatomy && (
        <section className={styles.block}>
          <h3 className={styles.title}>ja4 anatomy</h3>
          <table className={styles.anatomy}>
            <tbody>
              {anatomy.map((part) => (
                <tr key={part.field}>
                  <th scope="row">{part.field}</th>
                  <td className={styles.code}>{part.value}</td>
                  <td>{part.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {intel && intel.length > 0 && (
        <section className={styles.block}>
          <h3 className={styles.title}>intelligence</h3>
          {intel.map((report) => (
            <div
              key={`${report.kind}-${report.observed}`}
              className={styles.intel}
            >
              <div className={styles.intelHead}>
                <span className={styles.intelKind}>{report.kind}</span>
                <VerdictBadge verdict={report.verdict} />
                <span className={styles.score}>
                  threat {report.threat_score.toFixed(2)} / confidence{' '}
                  {report.confidence.toFixed(2)}
                </span>
              </div>
              {report.hits.map((hit) => (
                <div key={`${hit.source}-${hit.label}`} className={styles.hit}>
                  <span>{hit.label}</span>
                  <span className={styles.hitMeta}>
                    {hit.category} · {hit.strength.replace('_', ' ')} ·{' '}
                    {hit.source}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </section>
      )}

      {alerts && alerts.length > 0 && (
        <section className={styles.block}>
          <h3 className={styles.title}>alerts</h3>
          {alerts.map((alert) => (
            <div key={`${alert.rule}-${alert.ts_nanos}`} className={styles.alert}>
              <div className={styles.alertHead}>
                <SeverityTag severity={alert.severity} />
                <span className={styles.rule}>{alert.rule}</span>
              </div>
              <p className={styles.alertTitle}>{alert.title}</p>
              <p className={styles.alertDetail}>{alert.detail}</p>
            </div>
          ))}
        </section>
      )}
    </aside>
  )
}
