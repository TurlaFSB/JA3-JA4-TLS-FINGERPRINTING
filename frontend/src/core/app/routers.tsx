// ===================
// ©AngelaMos | 2026
// routers.tsx
// ===================

import { createBrowserRouter, type RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { ErrorPage } from './error-page'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    path: ROUTES.HOME,
    lazy: () => import('@/pages/landing'),
    errorElement: <ErrorPage />,
  },
  {
    element: <Shell />,
    errorElement: <ErrorPage />,
    children: [
      {
        path: ROUTES.SCOPE,
        lazy: () => import('@/pages/scope'),
      },
      {
        path: ROUTES.TRAFFIC,
        lazy: () => import('@/pages/traffic'),
      },
      {
        path: ROUTES.HOSTS,
        lazy: () => import('@/pages/hosts'),
      },
      {
        path: ROUTES.DNS,
        lazy: () => import('@/pages/dns'),
      },
      {
        path: ROUTES.ALERTS,
        lazy: () => import('@/pages/alerts'),
      },
      {
        path: ROUTES.LIBRARY,
        lazy: () => import('@/pages/library'),
      },
      {
        path: ROUTES.INTEL,
        lazy: () => import('@/pages/intel'),
      },
      {
        path: ROUTES.SENSOR,
        lazy: () => import('@/pages/sensor'),
      },
    ],
  },
  {
    path: '*',
    lazy: () => import('@/pages/landing'),
  },
]

export const router = createBrowserRouter(routes)
