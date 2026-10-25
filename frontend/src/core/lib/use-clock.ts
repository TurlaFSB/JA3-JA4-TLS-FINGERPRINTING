/**
 * © Pranav Verma | 2026
 * use-clock.ts
 */

import { useCallback } from 'react'
import { formatClock } from '@/api/types'
import { useTimeMode } from './shell.ui.store'

// Formats a nanosecond timestamp as a clock time in the zone the operator
// chose on the Sensor page.
export function useClock(): (tsNanos: number) => string {
  const utc = useTimeMode() === 'utc'
  return useCallback((tsNanos: number) => formatClock(tsNanos, utc), [utc])
}
