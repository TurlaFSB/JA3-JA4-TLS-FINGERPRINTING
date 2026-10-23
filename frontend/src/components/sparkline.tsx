/**
 * © Pranav Verma | 2026
 * sparkline.tsx
 */

import { cx } from './cx'
import styles from './sparkline.module.scss'

const WIDTH = 120
const HEIGHT = 26

// A throughput trace: one value per second, scaled to its own peak so a quiet
// link and a busy one both read clearly. Decorative; the number beside it is
// the accessible reading.
export function Sparkline({
  values,
  className,
}: {
  values: number[]
  className?: string
}): React.ReactElement {
  const peak = Math.max(1, ...values)
  const step = values.length > 1 ? WIDTH / (values.length - 1) : WIDTH
  const points = values
    .map((value, i) => {
      const x = (i * step).toFixed(1)
      const y = (HEIGHT - 2 - (value / peak) * (HEIGHT - 4)).toFixed(1)
      return `${x},${y}`
    })
    .join(' ')

  return (
    <svg
      className={cx(styles.spark, className)}
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <polyline
        className={styles.area}
        points={`0,${HEIGHT} ${points} ${WIDTH},${HEIGHT}`}
      />
      <polyline className={styles.line} points={points} />
    </svg>
  )
}
