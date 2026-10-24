/**
 * © Pranav Verma | 2026
 * error-page.tsx
 */

import { isRouteErrorResponse, useRouteError } from 'react-router-dom'
import styles from './error-page.module.scss'

// A page failed to load or render. The commonest cause is a tab left open
// across an update, so say that first and offer the one action that fixes it.
export function ErrorPage(): React.ReactElement {
  const error = useRouteError()
  const text =
    error instanceof Error
      ? error.message
      : isRouteErrorResponse(error)
        ? `${error.status} ${error.statusText}`
        : String(error)
  const stale =
    /dynamically imported module|Importing a module script failed/i.test(text)

  return (
    <main className={styles.page} role="alert">
      <h1 className={styles.title}>
        {stale ? 'The dashboard was updated' : 'This page could not be shown'}
      </h1>
      <p className={styles.body}>
        {stale
          ? 'This tab was opened before a new version was installed, so a file it needs is gone. Reloading loads the current version.'
          : 'Something went wrong while showing this page. Reloading often fixes it; if it keeps happening, the details below help a bug report.'}
      </p>
      <div className={styles.actions}>
        <button
          type="button"
          className={styles.primary}
          onClick={() => window.location.reload()}
        >
          Reload
        </button>
        <a className={styles.secondary} href="/scope">
          Go to Scope
        </a>
      </div>
      <pre className={styles.detail}>{text}</pre>
    </main>
  )
}
