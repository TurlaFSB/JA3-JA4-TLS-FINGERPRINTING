// ===========================
// ©AngelaMos | 2026
// App.tsx
// ===========================

import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { RouterProvider } from 'react-router-dom'
import { Toaster } from 'sonner'

import { queryClient } from '@/core/api'
import { router } from '@/core/app/routers'
import { resolveTheme, useTheme } from '@/core/lib/shell.ui.store'
import '@/core/app/toast.module.scss'

export default function App(): React.ReactElement {
  const painted = resolveTheme(useTheme())
  return (
    <QueryClientProvider client={queryClient}>
      <div className="app">
        <RouterProvider router={router} />
        <Toaster
          position="top-right"
          duration={2000}
          theme={painted}
          toastOptions={{
            style: {
              background: 'var(--ink-700)',
              border: '1px solid var(--line-strong)',
              color: 'var(--bone)',
            },
          }}
        />
      </div>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )
}
