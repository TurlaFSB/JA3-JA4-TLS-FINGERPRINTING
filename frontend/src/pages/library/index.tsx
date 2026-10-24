/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useLibrary } from '@/api/hooks'
import type { Capture, LibraryClient } from '@/api/types'
import { CropFrame, VerdictBadge } from '@/components'
import { API_BASE, ROUTES } from '@/config'
import styles from './library.module.scss'
import {
  CONFIDENCE_NOTE,
  formatAge,
  formatBytes,
  matchesCapture,
} from './library-data'

function useNow(): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 5000)
    return () => clearInterval(id)
  }, [])
  return now
}

function ClientRow({ client }: { client: LibraryClient }): React.ReactElement {
  const identity = client.known_as ?? client.guess.family.replace('_', ' ')
  return (
    <tr>
      <td className={styles.code}>{client.ja4}</td>
      <td>{client.transport}</td>
      <td className={styles.num}>{client.connections}</td>
      <td>
        {client.known_as ? (
          <span className={styles.exact}>{identity}</span>
        ) : (
          <span>{identity}</span>
        )}
        {client.verdict && client.known_as && (
          <>
            {' '}
            <VerdictBadge verdict={client.verdict} />
          </>
        )}
        {!client.known_as && client.guess.reasons.length > 0 && (
          <span className={styles.reason}>{client.guess.reasons[0]}</span>
        )}
      </td>
      <td className={styles.servers}>{client.servers.join(', ')}</td>
    </tr>
  )
}

function Detail({ capture }: { capture: Capture }): React.ReactElement {
  return (
    <div className={styles.detail}>
      {capture.error && <p className={styles.error}>{capture.error}</p>}
      {capture.headline?.caveat && (
        <p className={styles.caveat}>{capture.headline.caveat}</p>
      )}
      {capture.clients.length === 0 ? (
        <p className={styles.muted}>No TLS or QUIC client hellos in this file.</p>
      ) : (
        <table className={styles.clients}>
          <thead>
            <tr>
              <th scope="col">ja4</th>
              <th scope="col">via</th>
              <th scope="col">conn.</th>
              <th scope="col">identified as</th>
              <th scope="col">servers</th>
            </tr>
          </thead>
          <tbody>
            {capture.clients.map((client) => (
              <ClientRow key={client.ja4} client={client} />
            ))}
          </tbody>
        </table>
      )}
      {capture.status === 'ready' && (
        <a
          className={styles.report}
          href={`${API_BASE}/library/${encodeURIComponent(capture.id)}/report`}
          download="tlsfp-report.html"
        >
          Download report (HTML)
        </a>
      )}
      <p className={styles.muted}>
        {capture.frames.toLocaleString()} frames,{' '}
        {capture.tls_handshakes.toLocaleString()} TLS handshakes,{' '}
        {capture.quic_initials.toLocaleString()} QUIC Initials. The file is read
        for analysis only; nothing from it is stored or alerted.
      </p>
    </div>
  )
}

export function Component(): React.ReactElement {
  const { data, isLoading, isError } = useLibrary()
  const now = useNow()
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const files = data?.files ?? []
  const shown = useMemo(
    () => files.filter((file) => matchesCapture(file, query)),
    [files, query]
  )

  const status = isError
    ? 'the server did not answer'
    : data?.scanning
      ? 'scanning'
      : data?.scanned_unix
        ? `scanned ${formatAge(data.scanned_unix, now)}`
        : 'waiting for the first scan'

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>captures / library</span>
        <h1 className={styles.title}>Capture library</h1>
        <p className={styles.sub}>
          Capture files found in the folders the server watches, each read once
          and matched to the client that made it. New files appear on their own.
        </p>
      </section>

      <CropFrame
        label="captures // identified"
        aside={<span className={styles.aside}>{status}</span>}
        className={styles.frame}
      >
        <div className={styles.controls}>
          <input
            type="search"
            className={styles.search}
            placeholder="filter by file, client, server name or fingerprint"
            aria-label="Filter the capture library"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <span className={styles.count}>
            {shown.length === files.length
              ? `${files.length} file${files.length === 1 ? '' : 's'}`
              : `${shown.length} of ${files.length}`}
          </span>
        </div>

        {isLoading ? (
          <p className={styles.idle}>loading</p>
        ) : data && data.directories === 0 ? (
          <div className={styles.idle}>
            <p>No capture folder is configured.</p>
            <p className={styles.muted}>
              Start the server with <code>--library DIR</code> (or set{' '}
              <code>TLSFP_LIBRARY</code>). With Docker, put capture files in{' '}
              <code>~/tlsfp-captures</code> (Windows: the{' '}
              <code>tlsfp-captures</code> folder in your user profile, where the
              capture script saves them) and the library fills itself. See{' '}
              <Link to={ROUTES.SCOPE}>Scope</Link> for live traffic.
            </p>
          </div>
        ) : files.length === 0 ? (
          <p className={styles.idle}>
            {data?.scanning
              ? 'scanning the folder'
              : 'no .pcap or .pcapng files in the watched folders yet'}
          </p>
        ) : shown.length === 0 ? (
          <p className={styles.idle}>no capture matches this filter</p>
        ) : (
          <div className={styles.table}>
            <div className={styles.head} aria-hidden="true">
              <span>file</span>
              <span>detected client</span>
              <span>basis</span>
              <span className={styles.num}>handshakes</span>
              <span className={styles.num}>size</span>
              <span>modified</span>
            </div>
            {shown.map((file) => {
              const expanded = open === file.id
              return (
                <div key={file.id} className={styles.item}>
                  <button
                    type="button"
                    className={styles.row}
                    aria-expanded={expanded}
                    onClick={() => setOpen(expanded ? null : file.id)}
                  >
                    <span className={styles.name} title={file.name}>
                      {file.name}
                    </span>
                    <span className={styles.client}>
                      {file.status !== 'ready'
                        ? file.status.replace('_', ' ')
                        : (file.headline?.text ?? 'no client hellos')}
                    </span>
                    <span>
                      {file.headline && (
                        <span
                          className={styles.basis}
                          data-basis={file.headline.basis}
                          title={`${CONFIDENCE_NOTE[file.headline.confidence]}`}
                        >
                          {file.headline.basis} · {file.headline.confidence}
                        </span>
                      )}
                    </span>
                    <span className={styles.num}>
                      {(
                        file.tls_handshakes + file.quic_initials
                      ).toLocaleString()}
                    </span>
                    <span className={styles.num}>{formatBytes(file.size)}</span>
                    <span>{formatAge(file.modified_unix, now)}</span>
                  </button>
                  {expanded && <Detail capture={file} />}
                </div>
              )
            })}
          </div>
        )}
      </CropFrame>
    </div>
  )
}

Component.displayName = 'Library'
