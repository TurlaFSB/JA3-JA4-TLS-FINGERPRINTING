/**
 * © Pranav Verma | 2026
 * own-name.tsx
 */

import { createContext, useContext, useMemo } from 'react'
import { useCapture, useMeta } from '@/api/hooks'

type OwnName = (host: string) => string | null

const none: OwnName = () => null

const OwnNameContext = createContext<OwnName>(none)

// Names the addresses this computer owns ("my-laptop") and says nothing about
// any other. It is worked out once here, from one subscription to the capture
// and meta queries, and handed down: a row of a long list must not subscribe to
// the server itself, or every poll re-renders every row.
export function OwnNameProvider({
  children,
}: {
  children: React.ReactNode
}): React.ReactElement {
  const { data: capture } = useCapture()
  const { data: meta } = useMeta()
  const addresses = (capture?.own_addresses ?? []).join(',')
  const name = meta?.hostname ?? null
  const lookup = useMemo<OwnName>(() => {
    if (name === null || addresses === '') return none
    const own = new Set(addresses.split(','))
    return (host) => (own.has(host) ? name : null)
  }, [addresses, name])
  return (
    <OwnNameContext.Provider value={lookup}>{children}</OwnNameContext.Provider>
  )
}

export function useOwnName(): OwnName {
  return useContext(OwnNameContext)
}
