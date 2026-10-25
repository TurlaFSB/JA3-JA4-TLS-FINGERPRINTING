/**
 * © Pranav Verma | 2026
 * profiles.tsx
 */

import { useMemo, useState } from 'react'
import type { LiveItem } from '@/api/hooks'
import { decodeJa4 } from '@/api/types'
import { useClock } from '@/core/lib/use-clock'
import { VerdictBadge } from './atoms'
import { cx } from './cx'
import { CropFrame } from './marks'
import {
  type Comparison,
  compare,
  type DestinationProfile,
  destinationsCsv,
  download,
  type FingerprintProfile,
  fingerprintsCsv,
  summarise,
  timeline,
  topEntries,
  VERDICT_NOTE,
} from './profile-data'
import styles from './profiles.module.scss'

type Tab = 'fingerprints' | 'destinations'

const COLLAPSED_ROWS = 10

function plural(count: number, word: string): string {
  return `${count.toLocaleString()} ${word}${count === 1 ? '' : 's'}`
}

function Timeline({ times }: { times: number[] }): React.ReactElement {
  const clock = useClock()
  const bars = timeline(times)
  const peak = Math.max(1, ...bars.map((bar) => bar.count))
  const width = 240
  const step = width / bars.length
  return (
    <figure className={styles.timeline}>
      <svg
        viewBox={`0 0 ${width} 36`}
        role="img"
        aria-label={`Connections over time, ${times.length} in total`}
      >
        {bars.map(({ id, count }) => {
          const height = count === 0 ? 0 : Math.max(2, (count / peak) * 34)
          return (
            <rect
              key={id}
              x={id * step + 0.5}
              y={36 - height}
              width={Math.max(1, step - 1)}
              height={height}
            >
              <title>{plural(count, 'connection')}</title>
            </rect>
          )
        })}
      </svg>
      <figcaption>
        <span>{clock(Math.min(...times))}</span>
        <span>{clock(Math.max(...times))}</span>
      </figcaption>
    </figure>
  )
}

function FingerprintDetail({
  fp,
  onShow,
}: {
  fp: FingerprintProfile
  onShow: (value: string) => void
}): React.ReactElement {
  const clock = useClock()
  const anatomy = decodeJa4(fp.ja4)
  return (
    <div className={styles.detail}>
      <p className={styles.note}>{VERDICT_NOTE[fp.verdict]}</p>
      <div className={styles.actions}>
        <button
          type="button"
          className={styles.chip}
          onClick={() => onShow(fp.ja4)}
        >
          show in stream
        </button>
      </div>
      <div className={styles.cols}>
        <div>
          <h4 className={styles.sub}>seen</h4>
          <dl className={styles.facts}>
            <dt>connections</dt>
            <dd>{fp.connections.toLocaleString()}</dd>
            <dt>first</dt>
            <dd>{clock(fp.firstNanos)}</dd>
            <dt>last</dt>
            <dd>{clock(fp.lastNanos)}</dd>
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
          <h4 className={styles.sub}>over time</h4>
          <Timeline times={fp.times} />
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
  onShow,
}: {
  dest: DestinationProfile
  onShow: (value: string) => void
}): React.ReactElement {
  const clock = useClock()
  return (
    <div className={styles.detail}>
      <div className={styles.actions}>
        <button
          type="button"
          className={styles.chip}
          onClick={() => onShow(dest.name)}
        >
          show in stream
        </button>
      </div>
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
            <dd>{clock(dest.lastNanos)}</dd>
            <dt>sources</dt>
            <dd>{[...dest.sources].slice(0, 4).join(', ')}</dd>
          </dl>
        </div>
      </div>
    </div>
  )
}

function DiffList({
  title,
  diff,
  nameA,
  nameB,
}: {
  title: string
  diff: Comparison['ciphers']
  nameA: string
  nameB: string
}): React.ReactElement {
  const same = diff.onlyA.length === 0 && diff.onlyB.length === 0
  return (
    <div className={styles.diff}>
      <h4 className={styles.sub}>
        {title} · {diff.both} in common
      </h4>
      {same ? (
        <p className={styles.same}>identical</p>
      ) : (
        <div className={styles.diffCols}>
          <ul className={styles.onlyA}>
            <li className={styles.diffHead}>only in {nameA}</li>
            {diff.onlyA.length === 0 && <li className={styles.none}>none</li>}
            {diff.onlyA.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <ul className={styles.onlyB}>
            <li className={styles.diffHead}>only in {nameB}</li>
            {diff.onlyB.length === 0 && <li className={styles.none}>none</li>}
            {diff.onlyB.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function shortName(fp: FingerprintProfile): string {
  return fp.labels[0] ?? `${fp.ja4.slice(0, 12)}…`
}

function ComparePanel({
  a,
  b,
  onClear,
}: {
  a: FingerprintProfile
  b: FingerprintProfile
  onClear: () => void
}): React.ReactElement {
  const diff = compare(a, b)
  const partsA = decodeJa4(a.ja4)
  const partsB = decodeJa4(b.ja4)
  const nameA = shortName(a)
  const nameB = shortName(b)
  return (
    <section className={styles.compare} aria-label="Fingerprint comparison">
      <header className={styles.compareHead}>
        <h3 className={styles.compareTitle}>
          <span className={styles.tagA}>A</span> {nameA}
          <span className={styles.versus}>vs</span>
          <span className={styles.tagB}>B</span> {nameB}
        </h3>
        <button type="button" className={styles.chip} onClick={onClear}>
          clear comparison
        </button>
      </header>
      <p className={styles.note}>
        {a.ja4 === b.ja4
          ? 'The two are the same fingerprint.'
          : `${diff.ciphers.onlyA.length + diff.ciphers.onlyB.length} cipher and ${diff.extensions.onlyA.length + diff.extensions.onlyB.length} extension differences. ${diff.sharedDestinations.length} shared destination${diff.sharedDestinations.length === 1 ? '' : 's'}.`}
      </p>
      <table className={styles.matrix}>
        <thead>
          <tr>
            <th scope="col">field</th>
            <th scope="col">A</th>
            <th scope="col">B</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row">ja4</th>
            <td className={styles.code}>{a.ja4}</td>
            <td className={styles.code}>{b.ja4}</td>
          </tr>
          <tr>
            <th scope="row">verdict</th>
            <td>
              <VerdictBadge verdict={a.verdict} />
            </td>
            <td>
              <VerdictBadge verdict={b.verdict} />
            </td>
          </tr>
          <tr>
            <th scope="row">connections</th>
            <td>{a.connections}</td>
            <td>{b.connections}</td>
          </tr>
          <tr>
            <th scope="row">ja3 variants</th>
            <td>{a.ja3.size}</td>
            <td>{b.ja3.size}</td>
          </tr>
          {partsA &&
            partsB &&
            partsA.map((part, index) => {
              const other = partsB[index]
              const differs = part.value !== other.value
              return (
                <tr key={part.field} data-differs={differs}>
                  <th scope="row">{part.field}</th>
                  <td>{part.meaning}</td>
                  <td>{other.meaning}</td>
                </tr>
              )
            })}
        </tbody>
      </table>
      <div className={styles.diffGrid}>
        <DiffList
          title="cipher suites"
          diff={diff.ciphers}
          nameA={nameA}
          nameB={nameB}
        />
        <DiffList
          title="extensions"
          diff={diff.extensions}
          nameA={nameA}
          nameB={nameB}
        />
        <DiffList
          title="signature algorithms"
          diff={diff.signatures}
          nameA={nameA}
          nameB={nameB}
        />
      </div>
    </section>
  )
}

export function Profiles({
  feed,
  onShowInStream,
  className,
}: {
  feed: LiveItem[]
  onShowInStream: (value: string) => void
  className?: string
}): React.ReactElement {
  const [tab, setTab] = useState<Tab>('fingerprints')
  const [open, setOpen] = useState<string | null>(null)
  const [all, setAll] = useState(false)
  const [picked, setPicked] = useState<string[]>([])
  const profiles = useMemo(() => summarise(feed), [feed])

  const rows: (FingerprintProfile | DestinationProfile)[] =
    tab === 'fingerprints' ? profiles.fingerprints : profiles.destinations
  const shown = all ? rows : rows.slice(0, COLLAPSED_ROWS)
  const pair = picked
    .map((ja4) => profiles.fingerprints.find((fp) => fp.ja4 === ja4))
    .filter((fp): fp is FingerprintProfile => fp !== undefined)

  const togglePick = (ja4: string): void =>
    setPicked((prev) =>
      prev.includes(ja4)
        ? prev.filter((x) => x !== ja4)
        : [...prev, ja4].slice(-2)
    )

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
      label="clients and destinations"
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

      {tab === 'fingerprints' && pair.length === 2 && (
        <ComparePanel a={pair[0]} b={pair[1]} onClear={() => setPicked([])} />
      )}
      {tab === 'fingerprints' && pair.length === 1 && (
        <p className={styles.hintBar}>
          pick one more fingerprint with its checkbox to compare
        </p>
      )}

      {rows.length === 0 ? (
        <p className={styles.empty}>
          client hellos appear here as they cross the wire
        </p>
      ) : (
        <div className={styles.table}>
          <div className={cx(styles.line, styles.head)} aria-hidden="true">
            <span className={styles.pick} />
            <div className={styles.row}>
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
          </div>
          {shown.map((row) => {
            const key = 'ja4' in row ? row.ja4 : row.name
            const expanded = open === key
            return (
              <div key={key} className={styles.item}>
                <div className={styles.line}>
                  <span className={styles.pick}>
                    {'ja4' in row && (
                      <input
                        type="checkbox"
                        aria-label={`Compare ${row.ja4}`}
                        checked={picked.includes(row.ja4)}
                        onChange={() => togglePick(row.ja4)}
                      />
                    )}
                  </span>
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
                </div>
                {expanded &&
                  ('ja4' in row ? (
                    <FingerprintDetail fp={row} onShow={onShowInStream} />
                  ) : (
                    <DestinationDetail dest={row} onShow={onShowInStream} />
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
