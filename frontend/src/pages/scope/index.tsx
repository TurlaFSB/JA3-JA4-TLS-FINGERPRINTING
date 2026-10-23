/**
 * ©AngelaMos | 2026
 * index.tsx
 */

import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useLiveStream } from '@/api/hooks'
import {
  AnomalyHighlights,
  Distribution,
  LiveStream,
  Profiles,
  StatCluster,
} from '@/components'
import styles from './scope.module.scss'

export function Component(): React.ReactElement {
  const live = useLiveStream()
  const [params] = useSearchParams()
  const [query, setQuery] = useState(params.get('q') ?? '')

  // Filters the stream to one fingerprint or server name and brings it into view.
  const showInStream = (value: string): void => {
    setQuery(value)
    document
      .getElementById('live-stream-filter')
      ?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }

  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <img
          src="/assets/objects/xray-butterfly.png"
          alt=""
          className={styles.butterfly}
        />
        <div className={styles.headText}>
          <span className={styles.over}>live</span>
          <h1 className={styles.title}>Scope</h1>
          <p className={styles.sub}>
            TLS and QUIC handshakes as they cross the sensor, matched against the
            intelligence feed. Alerts are on their own page.
          </p>
        </div>
        <StatCluster
          flowCount={live.flowCount}
          rate={live.rate}
          className={styles.stats}
        />
      </section>

      <section className={styles.grid}>
        <LiveStream
          feed={live.feed}
          connected={live.connected}
          flowCount={live.flowCount}
          query={query}
          onQuery={setQuery}
          className={styles.live}
        />
        <AnomalyHighlights className={styles.anomaly} />
        <Distribution className={styles.dist} />
        <Profiles
          feed={live.feed}
          onShowInStream={showInStream}
          className={styles.profiles}
        />
      </section>
    </div>
  )
}

Component.displayName = 'Scope'
