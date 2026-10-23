/**
 * ©AngelaMos | 2026
 * stat-cluster.tsx
 */

import { useStats } from '@/api/hooks'
import { cx } from './cx'
import { Sparkline } from './sparkline'
import styles from './stat-cluster.module.scss'

export function StatCluster({
  flowCount,
  rate,
  className,
}: {
  flowCount: number
  rate: number[]
  className?: string
}): React.ReactElement {
  const { data } = useStats()
  const perSecond = rate.length > 0 ? rate[rate.length - 1] : 0
  const stats = [
    {
      value: data?.intel.total ?? 0,
      label: 'fingerprints',
      sub: 'in the intelligence feed',
    },
    {
      value: data?.alert_total ?? 0,
      label: 'alerts',
      sub: 'recorded by the rules',
    },
    {
      value: data?.intel.sources.length ?? 0,
      label: 'feeds',
      sub: 'intelligence sources',
    },
    {
      value: flowCount,
      label: 'handshakes',
      sub: `${perSecond}/s now`,
      trace: rate,
    },
  ]

  return (
    <div className={cx(styles.cluster, className)}>
      {stats.map((stat) => (
        <div key={stat.label} className={styles.stat}>
          <span className={styles.value}>{stat.value.toLocaleString()}</span>
          <span className={styles.label}>{stat.label}</span>
          <span className={styles.sub}>{stat.sub}</span>
          {'trace' in stat && stat.trace && (
            <Sparkline values={stat.trace} className={styles.trace} />
          )}
        </div>
      ))}
    </div>
  )
}
