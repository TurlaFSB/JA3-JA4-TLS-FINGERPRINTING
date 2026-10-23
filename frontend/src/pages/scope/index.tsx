/**
 * ©AngelaMos | 2026
 * index.tsx
 */

import { useState } from 'react'
import { useLiveStream } from '@/api/hooks'
import {
  AlertFeed,
  AnomalyHighlights,
  Distribution,
  LiveStream,
  Profiles,
  StatCluster,
} from '@/components'
import styles from './scope.module.scss'

export function Component(): React.ReactElement {
  const live = useLiveStream()
  const [query, setQuery] = useState('')

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
          <span className={styles.over}>passive tls surveillance / live</span>
          <h1 className={styles.title}>THE SCOPE</h1>
          <p className={styles.sub}>
            Fingerprints crossing the wire, scored against the corpus and read for
            the lie they tell.
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
        <AlertFeed className={styles.alerts} />
      </section>
    </div>
  )
}

Component.displayName = 'Scope'
