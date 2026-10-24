/**
 * ©AngelaMos | 2026
 * shell.tsx
 */

import { Suspense, useEffect, useState } from 'react'
import { ErrorBoundary, type FallbackProps } from 'react-error-boundary'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useMeta, useStats } from '@/api/hooks'
import { describeSource } from '@/api/types'
import { cx, RegMark } from '@/components'
import { ROUTES } from '@/config'
import { resolveTheme, useTheme, useUIStore } from '@/core/lib/shell.ui.store'
import styles from './shell.module.scss'

const NAV = [
  { to: ROUTES.SCOPE, label: 'scope' },
  { to: ROUTES.TRAFFIC, label: 'traffic' },
  { to: ROUTES.HOSTS, label: 'hosts' },
  { to: ROUTES.ALERTS, label: 'alerts' },
  { to: ROUTES.LIBRARY, label: 'library' },
  { to: ROUTES.INTEL, label: 'intel' },
]

function pad(value: number): string {
  return String(value).padStart(2, '0')
}

function useNow(): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

function formatUptime(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const days = Math.floor(hours / 24)
  if (days > 0) return `${days}d ${pad(hours % 24)}h`
  return `${pad(hours)}:${pad(minutes)}:${pad(total % 60)}`
}

// The sensor's real, live state: whether the backend answers, what it is
// reading from, how long it has been up, and the operator's own location label
// when one was set. Nothing here is guessed or hardcoded.
function SensorStatus(): React.ReactElement {
  const { data, isSuccess } = useMeta()
  const now = useNow()
  const date = new Date(now)
  return (
    <>
      <span className={cx(styles.link, isSuccess && styles.linkOn)}>
        {isSuccess ? 'online' : 'offline'}
      </span>
      {data && (
        <span className={styles.source} title={`tlsfp ${data.version}`}>
          {describeSource(data)}
        </span>
      )}
      {data?.location && <span className={styles.where}>{data.location}</span>}
      {data && (
        <span className={styles.uptime}>
          up {formatUptime(now - data.started_unix_ms)}
        </span>
      )}
      <span className={styles.clock}>
        {pad(date.getUTCHours())}:{pad(date.getUTCMinutes())}:
        {pad(date.getUTCSeconds())} utc
      </span>
    </>
  )
}

// Applies the chosen theme to the document and offers the switch.
function ThemeToggle(): React.ReactElement {
  const theme = useTheme()
  const setTheme = useUIStore((state) => state.setTheme)
  const painted = resolveTheme(theme)
  useEffect(() => {
    document.documentElement.dataset.theme = painted
  }, [painted])
  const next = painted === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      className={styles.theme}
      onClick={() => setTheme(next)}
      aria-label={`Switch to the ${next} theme`}
      title={`Switch to the ${next} theme`}
    >
      {painted}
    </button>
  )
}

function ShellError({ error }: FallbackProps): React.ReactElement {
  const message = error instanceof Error ? error.message : String(error)
  return (
    <div className={styles.crash}>
      <span className={styles.crashTag}>signal lost</span>
      <pre className={styles.crashMsg}>{message}</pre>
    </div>
  )
}

function ShellLoading(): React.ReactElement {
  return <div className={styles.loading}>acquiring</div>
}

const TITLES: Record<string, string> = {
  [ROUTES.SCOPE]: 'Live scope',
  [ROUTES.TRAFFIC]: 'Traffic',
  [ROUTES.HOSTS]: 'Hosts',
  [ROUTES.ALERTS]: 'Alerts',
  [ROUTES.LIBRARY]: 'Capture library',
  [ROUTES.INTEL]: 'Intelligence',
}

export function Shell(): React.ReactElement {
  const { pathname } = useLocation()
  const { data: stats } = useStats()
  const alertTotal = stats?.alert_total ?? 0
  useEffect(() => {
    document.title = `${TITLES[pathname] ?? 'Dashboard'} · tlsfp`
  }, [pathname])

  return (
    <div className={styles.shell}>
      <header className={styles.top}>
        <div className={styles.brand}>
          <RegMark className={styles.reg} />
          <NavLink to={ROUTES.HOME} className={styles.mark}>
            TLSFP
          </NavLink>
          <span className={styles.tagline}>passive tls surveillance</span>
        </div>

        <nav className={styles.nav}>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cx(styles.tab, isActive && styles.tabOn)
              }
            >
              {item.label}
              {item.to === ROUTES.ALERTS && alertTotal > 0 && (
                <span className={styles.badge}>
                  {alertTotal.toLocaleString()}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className={styles.status}>
          <SensorStatus />
          <ThemeToggle />
        </div>
      </header>

      <main className={styles.main}>
        <ErrorBoundary FallbackComponent={ShellError}>
          <Suspense fallback={<ShellLoading />}>
            <Outlet />
          </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  )
}
