/**
 * ©AngelaMos | 2025
 * ui.store.ts
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

type Theme = 'light' | 'dark' | 'system'
export type TimeMode = 'local' | 'utc'
export type TextSize = 'small' | 'normal' | 'large'

interface UIState {
  theme: Theme
  sidebarOpen: boolean
  sidebarCollapsed: boolean
  timeMode: TimeMode
  textSize: TextSize
  setTimeMode: (mode: TimeMode) => void
  setTextSize: (size: TextSize) => void
  setTheme: (theme: Theme) => void
  toggleSidebar: () => void
  setSidebarOpen: (open: boolean) => void
  toggleSidebarCollapsed: () => void
}

export const useUIStore = create<UIState>()(
  devtools(
    persist(
      (set) => ({
        theme: 'dark',
        sidebarOpen: false,
        sidebarCollapsed: false,
        timeMode: 'local',
        textSize: 'normal',

        setTimeMode: (timeMode) => set({ timeMode }, false, 'ui/setTimeMode'),

        setTextSize: (textSize) => set({ textSize }, false, 'ui/setTextSize'),

        setTheme: (theme) => set({ theme }, false, 'ui/setTheme'),

        toggleSidebar: () =>
          set(
            (state) => ({ sidebarOpen: !state.sidebarOpen }),
            false,
            'ui/toggleSidebar'
          ),

        setSidebarOpen: (open) =>
          set({ sidebarOpen: open }, false, 'ui/setSidebarOpen'),

        toggleSidebarCollapsed: () =>
          set(
            (state) => ({ sidebarCollapsed: !state.sidebarCollapsed }),
            false,
            'ui/toggleSidebarCollapsed'
          ),
      }),
      {
        name: 'ui-storage',
        partialize: (state) => ({
          theme: state.theme,
          sidebarCollapsed: state.sidebarCollapsed,
          timeMode: state.timeMode,
          textSize: state.textSize,
        }),
      }
    ),
    { name: 'UIStore' }
  )
)

export const useTheme = (): Theme => useUIStore((s) => s.theme)
export const useTimeMode = (): TimeMode => useUIStore((s) => s.timeMode)
export const useTextSize = (): TextSize => useUIStore((s) => s.textSize)
export const useSidebarOpen = (): boolean => useUIStore((s) => s.sidebarOpen)
export const useSidebarCollapsed = (): boolean =>
  useUIStore((s) => s.sidebarCollapsed)

// The theme actually painted: "system" follows the operating system setting.
export function resolveTheme(theme: Theme): 'light' | 'dark' {
  if (theme !== 'system') return theme
  return typeof window !== 'undefined' &&
    window.matchMedia?.('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark'
}
