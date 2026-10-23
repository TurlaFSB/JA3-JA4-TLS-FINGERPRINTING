/**
 * ©AngelaMos | 2026
 * profiles.tsx
 */

import { useMemo, useState } from 'react'
import type { LiveItem } from '@/api/hooks'
import { decodeJa4, formatClock } from '@/api/types'
import { VerdictBadge } from './atoms'
import { cx } from './cx'
import { CropFrame } from './marks'
import {
  type DestinationProfile,
  destinationsCsv,
  download,
  type FingerprintProfile,
  fingerprintsCsv,
  summarise,
  topEntries,
  VERDICT_NOTE,
} from './profile-data'
import styles from './profiles.module.scss'

type Tab = 'fingerprints' | 'destinations'

const COLLAPSED_ROWS = 10

function plural(count: number, word: string): string {
  return `${count.toLocaleString()} ${word}${count === 1 ? '' : 's'}`
}

function FingerprintDetail({
  fp,
}: {
  fp: FingerprintProfile
}): React.ReactElement {
  const anatomy = decodeJa4(fp.ja4)
  return (
    <div className={styles.detail}>
      <p className={styles.note}>{VERDICT_NOTE[fp.verdict]}</p>
      <div className={styles.cols}>
        <div>
          <h4 className={styles.sub}>seen</h4>
          <dl className={styles.facts}>
            <dt>connections</dt>
            <dd>{fp.connections.toLocaleString()}</dd>
            <dt>first</dt>
            <dd>{formatClock(fp.firstNanos)}</dd>
            <dt>last</dt>
            <dd>{formatClock(fp.lastNanos)}</dd>
            <dt>sources</dt>
            <dd>
              {topEntries(fp.sources, 4)
                .map(([h]) => h)
                .join(', ')}
            </dd>
            <dt>alpn</dt>
            <dd>{[...fp.alpn].join(', ') || 'none'}</dd>
            <dt>ja3 variants</dt>
            <dd>
              {fp.ja3.size.toLocaleString()}
              {fp.connections > 1 && fp.ja3.size > 1 && (
                <span className={styles.hint}>
                  {' '}
                  one JA4, many JA3: extension order is shuffled per connection
                </span>
              )}
              {fp.connections > 1 && fp.ja3.size === 1 && (
                <span className={styles.hint}>
                  {' '}
                  stable JA3: extension order is fixed
                </span>
              )}
            </dd>
          </dl>
          {fp.labels.length > 0 && (
            <>
              <h4 className={styles.sub}>exact intelligence matches</h4>
              <p className={styles.labels}>{fp.labels.join(' · ')}</p>
            </>
          )}
        </div>
        <div>
          <h4 className={styles.sub}>destinations</h4>
          <ul className={styles.list}>
            {topEntries(fp.destinations, 8).map(([name, count]) => (
              <li key={name}>
                <span className={styles.listName}>{name}</span>
                <span className={styles.listCount}>{count}</span>
              </li>
            ))}
          </ul>
        </div>
        {anatomy && (
          <div>
            <h4 className={styles.sub}>ja4 anatomy</h4>
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
          </div>
        )}
      </div>
    </div>
  )
}

function DestinationDetail({
  dest,
}: {
  dest: DestinationProfile
}): React.ReactElement {
  return (
    <div className={styles.detail}>
      <p className={styles.note}>
        {dest.fingerprints.size > 1
          ? `Reached with ${dest.fingerprints.size} different client fingerprints: different programs, or one program with variants such as resumed sessions and HTTP/3.`
          : 'Every connection used the same client fingerprint.'}
      </p>
      <div className={styles.cols}>
        <div>
          <h4 className={styles.sub}>client fingerprints</h4>
          <ul className={styles.list}>
            {topEntries(dest.fingerprints, 8).map(([ja4, count]) => (
              <li key={ja4}>
                <span className={styles.listName}>{ja4}</span>
                <span className={styles.listCount}>{count}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h4 className={styles.sub}>seen</h4>
          <dl className={styles.facts}>
            <dt>connections</dt>
            <dd>{dest.connections.toLocaleString()}</dd>
            <dt>last</dt>
            <dd>{formatClock(dest.lastNanos)}</dd>
            <dt>sources</dt>
            <dd>{[...dest.sources].slice(0, 4).join(', ')}</dd>
          </dl>
        </div>
      </div>
    </div>
  )
}

export function Profiles({
  feed,
  className,
}: {
  feed: LiveItem[]
  className?: string
}): React.ReactElement {
  const [tab, setTab] = useState<Tab>('fingerprints')
  const [open, setOpen] = useState<string | null>(null)
  const [all, setAll] = useState(false)
  const profiles = useMemo(() => summarise(feed), [feed])

  const rows: (FingerprintProfile | DestinationProfile)[] =
    tab === 'fingerprints' ? profiles.fingerprints : profiles.destinations
  const shown = all ? rows : rows.slice(0, COLLAPSED_ROWS)

  const exportCsv = (): void => {
    if (tab === 'fingerprints') {
      download('tlsfp-fingerprints.csv', fingerprintsCsv(profiles.fingerprints))
    } else {
      download('tlsfp-destinations.csv', destinationsCsv(profiles.destinations))
    }
  }

  const aside = (
    <span className={styles.aside}>
      {plural(profiles.fingerprints.length, 'fingerprint')} ·{' '}
      {plural(profiles.destinations.length, 'destination')}
    </span>
  )

  return (
    <CropFrame
      label="profiles // who is talking to whom"
      aside={aside}
      className={className}
    >
      <div className={styles.controls}>
        <fieldset className={styles.tabs}>
          <legend className={styles.srOnly}>Group by</legend>
          {(['fingerprints', 'destinations'] as const).map((id) => (
            <button
              key={id}
              type="button"
              className={cx(styles.chip, tab === id && styles.chipOn)}
              aria-pressed={tab === id}
              onClick={() => {
                setTab(id)
                setOpen(null)
                setAll(false)
              }}
            >
              {id === 'fingerprints' ? 'client fingerprints' : 'destinations'}
            </button>
          ))}
        </fieldset>
        <button
          type="button"
          className={styles.chip}
          onClick={exportCsv}
          disabled={rows.length === 0}
        >
          export csv
        </button>
      </div>

      {rows.length === 0 ? (
        <p className={styles.empty}>
          client hellos appear here as they cross the wire
        </p>
      ) : (
        <div className={styles.table}>
          <div className={cx(styles.row, styles.head)} aria-hidden="true">
            <span>{tab === 'fingerprints' ? 'ja4' : 'server name'}</span>
            <span>
              {tab === 'fingerprints' ? 'identified as' : 'fingerprints'}
            </span>
            <span className={styles.num}>conn.</span>
            <span className={styles.num}>
              {tab === 'fingerprints' ? 'dest.' : 'sources'}
            </span>
            <span>verdict</span>
          </div>
          {shown.map((row) => {
            const key = 'ja4' in row ? row.ja4 : row.name
            const expanded = open === key
            return (
              <div key={key} className={styles.item}>
                <button
                  type="button"
                  className={styles.row}
                  aria-expanded={expanded}
                  onClick={() => setOpen(expanded ? null : key)}
                >
                  <span className={styles.key} title={key}>
                    {key}
                  </span>
                  <span className={styles.what}>
                    {'ja4' in row
                      ? row.labels.join(' · ') || 'unidentified'
                      : plural(row.fingerprints.size, 'fingerprint')}
                  </span>
                  <span className={styles.num}>
                    {row.connections.toLocaleString()}
                  </span>
                  <span className={styles.num}>
                    {'ja4' in row ? row.destinations.size : row.sources.size}
                  </span>
                  <span>
                    <VerdictBadge verdict={row.verdict} />
                  </span>
                </button>
                {expanded &&
                  ('ja4' in row ? (
                    <FingerprintDetail fp={row} />
                  ) : (
                    <DestinationDetail dest={row} />
                  ))}
              </div>
            )
          })}
          {rows.length > COLLAPSED_ROWS && (
            <button
              type="button"
              className={styles.more}
              onClick={() => setAll(!all)}
            >
              {all ? 'show fewer' : `show all ${rows.length.toLocaleString()}`}
            </button>
          )}
        </div>
      )}
    </CropFrame>
  )
}
