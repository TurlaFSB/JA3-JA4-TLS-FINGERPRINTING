/**
 * © Pranav Verma | 2026
 * event-detail.tsx
 */

import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  type Alert,
  type ClientRead,
  decodeJa4,
  fingerprintOf,
  formatClock,
  type MatchReport,
  type StreamEvent,
  splitAddr,
  worstVerdict,
} from '@/api/types'
import { ROUTES } from '@/config'
import { SeverityTag, VerdictBadge } from './atoms'
import styles from './event-detail.module.scss'
import {
  type Connection,
  clientName,
  explain,
  intelNote,
  RULE_NOTE,
} from './stream-data'

interface Field {
  label: string
  value: string
  note?: string
}

const KIND_TITLE: Record<StreamEvent['kind'], string> = {
  client_hello: 'client hello',
  server_hello: 'server hello',
  certificate: 'certificate',
  http_request: 'http request',
  tcp_syn: 'tcp syn',
  tcp_syn_ack: 'tcp syn-ack',
}

const KIND_CODE: Record<StreamEvent['kind'], string> = {
  client_hello: 'CLT',
  server_hello: 'SRV',
  certificate: 'CRT',
  http_request: 'HTP',
  tcp_syn: 'SYN',
  tcp_syn_ack: 'SYK',
}

// What each fingerprint is, in a line, so a value is never just a hash.
const NOTE = {
  ja4: 'How the client builds its handshake: version, ciphers, extensions. Stable across runs of the same software.',
  ja4raw: 'The values the hash was made from, before hashing.',
  ja3: 'The older client fingerprint (an MD5 of the handshake). Changes whenever a browser shuffles its extensions.',
  ja3raw: 'The text the JA3 hash was made from.',
  ja4s: 'How the server answered: which version and cipher it chose.',
  ja3s: 'The older server fingerprint.',
  ja4x: 'How the certificate was built (issuer and subject fields and extensions), not who signed it.',
  ja4h: 'The shape of the HTTP request: method, version, header order and cookies.',
  ja4t: "The client operating system's TCP settings.",
  ja4ts: "The server's TCP settings.",
} as const

function fieldsOf(event: StreamEvent): Field[] {
  switch (event.kind) {
    case 'client_hello':
      return [
        { label: 'ja4', value: event.ja4.hash, note: NOTE.ja4 },
        { label: 'ja4 raw', value: event.ja4.raw, note: NOTE.ja4raw },
        { label: 'ja3', value: event.ja3, note: NOTE.ja3 },
        { label: 'ja3 raw', value: event.ja3_raw, note: NOTE.ja3raw },
      ]
    case 'server_hello':
      return [
        { label: 'ja4s', value: event.ja4s.hash, note: NOTE.ja4s },
        { label: 'ja4s raw', value: event.ja4s.raw },
        { label: 'ja3s', value: event.ja3s, note: NOTE.ja3s },
        { label: 'ja3s raw', value: event.ja3s_raw },
      ]
    case 'certificate':
      return [{ label: 'ja4x', value: event.ja4x, note: NOTE.ja4x }]
    case 'http_request':
      return [
        { label: 'ja4h', value: event.ja4h.hash, note: NOTE.ja4h },
        { label: 'ja4h raw', value: event.ja4h.raw },
      ]
    case 'tcp_syn':
      return [{ label: 'ja4t', value: event.ja4t, note: NOTE.ja4t }]
    case 'tcp_syn_ack':
      return [{ label: 'ja4ts', value: event.ja4ts, note: NOTE.ja4ts }]
  }
}

function details(event: StreamEvent, conn?: Connection): Field[] {
  const src = splitAddr(event.src)
  const dst = splitAddr(event.dst)
  const rows: Field[] = [
    { label: 'from', value: `${src.host} port ${src.port}` },
    { label: 'to', value: `${dst.host} port ${dst.port}` },
  ]
  const site =
    (event.kind === 'client_hello' ? event.sni : undefined) ?? conn?.sni
  if (site) rows.push({ label: 'site', value: site })
  if (event.kind === 'client_hello' && event.alpn) {
    rows.push({
      label: 'protocol',
      value: event.alpn,
      note: 'The application protocol the client offered: h2 is HTTP/2, h3 is HTTP/3 over QUIC.',
    })
  }
  if (event.kind === 'http_request') {
    rows.push({ label: 'method', value: event.method })
    if (event.host) rows.push({ label: 'host', value: event.host })
    if (event.user_agent) {
      rows.push({ label: 'user-agent', value: event.user_agent })
    }
  }
  if (conn && conn.transport !== 'unknown') {
    rows.push({
      label: 'transport',
      value: conn.transport === 'quic' ? 'QUIC (UDP, HTTP/3)' : 'TCP (TLS)',
    })
  }
  return rows
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

function ClientBlock({ client }: { client: ClientRead }): React.ReactElement {
  const who = clientName(client)
  return (
    <section className={styles.block}>
      <h3 className={styles.title}>who is the client</h3>
      <p className={styles.lead} data-basis={who.basis}>
        {who.basis === 'none' ? client.family_name : who.text}
      </p>
      <p className={styles.note}>
        {who.basis === 'exact'
          ? 'Matched exactly against the intelligence feed.'
          : `Inferred from the shape of the handshake, with ${client.confidence} confidence. It is a family, not a version.`}
      </p>
      {client.reasons.length > 0 && (
        <ul className={styles.reasons}>
          {client.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      )}
      {client.caveat && <p className={styles.caveat}>{client.caveat}</p>}
    </section>
  )
}

export function EventDetail({
  event,
  intel,
  alerts,
  client,
  conn,
  onClose,
  onFilter,
  onOpen,
  onPrev,
  onNext,
  position,
}: {
  event: StreamEvent
  intel?: MatchReport[]
  alerts?: Alert[]
  client?: ClientRead
  conn?: Connection
  onClose: () => void
  onFilter: (value: string) => void
  onOpen: (seq: number) => void
  onPrev?: () => void
  onNext?: () => void
  position?: string
}): React.ReactElement {
  const closeRef = useRef<HTMLButtonElement>(null)
  const fields = fieldsOf(event)
  const facts = details(event, conn)
  const anatomy = event.kind === 'client_hello' ? decodeJa4(event.ja4.hash) : null
  const verdict = worstVerdict(intel)
  const shownClient = client ?? conn?.client
  const fingerprint = fingerprintOf(event)
  const src = splitAddr(event.src)
  const site =
    (event.kind === 'client_hello' ? event.sni : undefined) ?? conn?.sni
  const related = (conn?.items ?? []).filter(
    (item) => item.message.event !== event
  )

  // Keyboard: Esc closes, arrow keys step through the stream.
  useEffect(() => {
    const onKey = (key: KeyboardEvent): void => {
      const target = key.target as HTMLElement | null
      if (target instanceof HTMLInputElement) return
      if (key.key === 'Escape') onClose()
      else if (key.key === 'ArrowUp' || key.key === 'k') onPrev?.()
      else if (key.key === 'ArrowDown' || key.key === 'j') onNext?.()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose, onPrev, onNext])

  useEffect(() => {
    closeRef.current?.focus()
  }, [])

  return (
    <aside
      className={styles.panel}
      role="dialog"
      aria-label={`${KIND_TITLE[event.kind]} detail`}
    >
      <header className={styles.head}>
        <div className={styles.headText}>
          <span className={styles.code}>{KIND_CODE[event.kind]}</span>
          <span className={styles.kind}>{KIND_TITLE[event.kind]}</span>
          <span className={styles.time}>{formatClock(event.ts_nanos)}</span>
        </div>
        <div className={styles.nav}>
          {position && <span className={styles.position}>{position}</span>}
          <button
            type="button"
            className={styles.copy}
            onClick={onPrev}
            disabled={!onPrev}
            aria-label="Newer event"
            title="Newer (up or k)"
          >
            up
          </button>
          <button
            type="button"
            className={styles.copy}
            onClick={onNext}
            disabled={!onNext}
            aria-label="Older event"
            title="Older (down or j)"
          >
            down
          </button>
          <button
            ref={closeRef}
            type="button"
            className={styles.close}
            onClick={onClose}
            aria-label="Close detail"
            title="Close (Esc)"
          >
            close
          </button>
        </div>
      </header>

      <p className={styles.summary}>{explain(event, conn)}</p>

      <div className={styles.actions}>
        <button
          type="button"
          className={styles.action}
          onClick={() => onFilter(fingerprint.value)}
        >
          only this fingerprint
        </button>
        {site && (
          <button
            type="button"
            className={styles.action}
            onClick={() => onFilter(site)}
          >
            only this site
          </button>
        )}
        <Link
          className={styles.action}
          to={`${ROUTES.HOSTS}?ip=${encodeURIComponent(src.host)}`}
        >
          history of {src.host.length > 22 ? 'this host' : src.host}
        </Link>
      </div>

      <section className={styles.block}>
        <h3 className={styles.title}>connection</h3>
        <dl className={styles.facts}>
          {facts.map((fact) => (
            <div key={fact.label} className={styles.fact} title={fact.note}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          ))}
        </dl>
      </section>

      {shownClient && event.kind === 'client_hello' && (
        <ClientBlock client={shownClient} />
      )}

      <section className={styles.block}>
        <h3 className={styles.title}>fingerprints</h3>
        <dl className={styles.fields}>
          {fields.map((field) => (
            <div key={field.label} className={styles.field}>
              <dt>{field.label}</dt>
              <dd>
                <span className={styles.stack}>
                  <span className={styles.value}>{field.value}</span>
                  {field.note && (
                    <span className={styles.hint}>{field.note}</span>
                  )}
                </span>
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
                  <td className={styles.codeCell}>{part.value}</td>
                  <td>{part.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {related.length > 0 && (
        <section className={styles.block}>
          <h3 className={styles.title}>same connection</h3>
          <ul className={styles.relatedList}>
            {related.map((item) => {
              const fp = fingerprintOf(item.message.event)
              return (
                <li key={item.seq}>
                  <button
                    type="button"
                    className={styles.related}
                    onClick={() => onOpen(item.seq)}
                  >
                    <span className={styles.code}>
                      {KIND_CODE[item.message.event.kind]}
                    </span>
                    <span className={styles.relatedFp}>
                      {fp.kind} {fp.value}
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        </section>
      )}

      <section className={styles.block}>
        <h3 className={styles.title}>intelligence</h3>
        {intel && intel.length > 0 ? (
          intel.map((report) => (
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
          ))
        ) : (
          <p className={styles.note}>{verdict ? '' : intelNote(intel)}</p>
        )}
      </section>

      {alerts && alerts.length > 0 && (
        <section className={styles.block}>
          <h3 className={styles.title}>alerts raised</h3>
          {alerts.map((alert) => (
            <div key={`${alert.rule}-${alert.ts_nanos}`} className={styles.alert}>
              <div className={styles.alertHead}>
                <SeverityTag severity={alert.severity} />
                <span className={styles.rule}>{alert.rule}</span>
              </div>
              <p className={styles.alertTitle}>{alert.title}</p>
              <p className={styles.alertDetail}>{alert.detail}</p>
              <p className={styles.hint}>{RULE_NOTE[alert.rule]}</p>
            </div>
          ))}
        </section>
      )}
    </aside>
  )
}
