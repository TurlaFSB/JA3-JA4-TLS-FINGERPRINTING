// ===================
// ©AngelaMos | 2026
// index.ts
// ===================

import { type UseQueryResult, useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  API_BASE,
  API_ENDPOINTS,
  LIVE,
  QUERY_CONFIG,
  QUERY_KEYS,
  STREAM_URL,
} from '@/config'
import { apiClient } from '@/core/api'
import {
  type Alert,
  alertSchema,
  type CaptureView,
  type CatalogEntry,
  captureViewSchema,
  catalogEntrySchema,
  type DnsView,
  dnsViewSchema,
  type FpKind,
  type HostProfile,
  type HostSummary,
  hostProfileSchema,
  hostSummarySchema,
  type InterfacesView,
  interfacesViewSchema,
  isLiveMessage,
  type LibraryView,
  type LiveMessage,
  libraryViewSchema,
  type MetaResponse,
  metaSchema,
  type Observed,
  observedSchema,
  type StatsResponse,
  statsResponseSchema,
  type TrafficView,
  trafficViewSchema,
} from '../types'

async function getStats(): Promise<StatsResponse> {
  const { data } = await apiClient.get(API_ENDPOINTS.STATS)
  return statsResponseSchema.parse(data)
}

async function getMeta(): Promise<MetaResponse> {
  const { data } = await apiClient.get(API_ENDPOINTS.META)
  return metaSchema.parse(data)
}

async function getLibrary(): Promise<LibraryView> {
  const { data } = await apiClient.get(API_ENDPOINTS.LIBRARY)
  return libraryViewSchema.parse(data)
}

async function getAlerts(limit: number): Promise<Alert[]> {
  const { data } = await apiClient.get(API_ENDPOINTS.ALERTS, {
    params: { limit },
  })
  return alertSchema.array().parse(data)
}

async function getSearch(
  query: string,
  kind: string,
  limit: number
): Promise<CatalogEntry[]> {
  const { data } = await apiClient.get(API_ENDPOINTS.SEARCH, {
    params: { q: query, kind: kind || undefined, limit },
  })
  return catalogEntrySchema.array().parse(data)
}

export function useStats(): UseQueryResult<StatsResponse> {
  return useQuery({
    queryKey: QUERY_KEYS.STATS,
    queryFn: getStats,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

// What the sensor is doing right now: its feed, uptime origin and any operator
// label. A failed fetch means the backend is unreachable, which the header
// shows as offline.
export function useMeta(): UseQueryResult<MetaResponse> {
  return useQuery({
    queryKey: QUERY_KEYS.META,
    queryFn: getMeta,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT * 2,
    retry: QUERY_CONFIG.RETRY.NONE,
  })
}

// The capture files the server found in its library directories and what it
// identified in each. Polled, because the scan runs in the background.
export function useLibrary(): UseQueryResult<LibraryView> {
  return useQuery({
    queryKey: QUERY_KEYS.LIBRARY,
    queryFn: getLibrary,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

export function useRecentAlerts(
  limit: number = LIVE.ALERT_PAGE
): UseQueryResult<Alert[]> {
  return useQuery({
    queryKey: QUERY_KEYS.ALERTS(limit),
    queryFn: () => getAlerts(limit),
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

export function useSearch(
  query: string,
  kind: FpKind | ''
): UseQueryResult<CatalogEntry[]> {
  return useQuery({
    queryKey: QUERY_KEYS.SEARCH(query, kind),
    queryFn: () => getSearch(query, kind, LIVE.SEARCH_PAGE),
    placeholderData: (previous) => previous,
  })
}

// The href for a streamed export download, used directly by an anchor so the
// browser handles the file rather than buffering it through fetch.
export function exportHref(format: 'json' | 'csv', limit = 1000): string {
  return `${API_BASE}${API_ENDPOINTS.EXPORT}?format=${format}&limit=${limit}`
}

export interface LiveItem {
  seq: number
  message: LiveMessage
  // False for lines delivered as the connect-time backlog, which appear at
  // once rather than sliding in.
  animate: boolean
}

export interface LiveState {
  feed: LiveItem[]
  connected: boolean
  flowCount: number
  alertCount: number
  // Flows per second over the last RATE_WINDOW seconds, oldest first.
  rate: number[]
}

const EMPTY_LIVE: LiveState = {
  feed: [],
  connected: false,
  flowCount: 0,
  alertCount: 0,
  rate: Array.from({ length: LIVE.RATE_WINDOW }, () => 0),
}

function parseBacklog(data: string): LiveMessage[] {
  try {
    const parsed: unknown = JSON.parse(data)
    return Array.isArray(parsed) ? parsed.filter(isLiveMessage) : []
  } catch {
    return []
  }
}

function inlineAlertCount(message: LiveMessage): number {
  if (message.type === 'flow') return message.alerts?.length ?? 0
  return 1
}

function parseMessage(data: string): LiveMessage | null {
  try {
    const parsed: unknown = JSON.parse(data)
    return isLiveMessage(parsed) ? parsed : null
  } catch {
    return null
  }
}

// Subscribes to the Server-Sent Events stream and keeps a bounded, newest-first
// window of what has come over the wire, plus running counts for the masthead.
// EventSource reconnects on its own, so a dropped link recovers without help.
export function useLiveStream(maxItems: number = LIVE.STREAM_BUFFER): LiveState {
  const [state, setState] = useState<LiveState>(EMPTY_LIVE)
  const max = useRef(maxItems)
  max.current = maxItems
  const seq = useRef(0)
  const bucket = useRef(0)

  useEffect(() => {
    const tick = setInterval(() => {
      const count = bucket.current
      bucket.current = 0
      setState((prev) => ({ ...prev, rate: [...prev.rate.slice(1), count] }))
    }, 1000)
    return () => clearInterval(tick)
  }, [])

  useEffect(() => {
    const source = new EventSource(STREAM_URL)

    source.onopen = () => {
      setState((prev) => ({ ...prev, connected: true }))
    }

    source.onerror = () => {
      setState((prev) => ({ ...prev, connected: false }))
    }

    // On connect the server sends everything it remembers in one event, oldest
    // first. Showing it in a single update means a fresh page opens already
    // populated instead of replaying the past line by line.
    source.addEventListener('backlog', (event) => {
      const messages = parseBacklog((event as MessageEvent<string>).data)
      if (messages.length === 0) return
      const items: LiveItem[] = messages.map((message) => {
        seq.current += 1
        return { seq: seq.current, message, animate: false }
      })
      setState((prev) => ({
        feed: [...items.reverse(), ...prev.feed].slice(0, max.current),
        connected: true,
        flowCount:
          prev.flowCount + messages.filter((m) => m.type === 'flow').length,
        alertCount:
          prev.alertCount +
          messages.reduce((total, m) => total + inlineAlertCount(m), 0),
        rate: prev.rate,
      }))
    })

    source.onmessage = (event) => {
      const message = parseMessage(event.data)
      if (!message) return
      seq.current += 1
      if (message.type === 'flow') bucket.current += 1
      const item: LiveItem = { seq: seq.current, message, animate: true }
      setState((prev) => {
        const feed = [item, ...prev.feed].slice(0, max.current)
        const flowCount = prev.flowCount + (message.type === 'flow' ? 1 : 0)
        const inlineAlerts =
          message.type === 'flow' ? (message.alerts?.length ?? 0) : 0
        const standalone = message.type === 'alert' ? 1 : 0
        return {
          feed,
          connected: true,
          flowCount,
          alertCount: prev.alertCount + inlineAlerts + standalone,
          rate: prev.rate,
        }
      })
    }

    return () => {
      source.close()
    }
  }, [])

  return state
}

async function getTraffic(): Promise<TrafficView> {
  const { data } = await apiClient.get(API_ENDPOINTS.TRAFFIC, {
    params: { limit: 500 },
  })
  return trafficViewSchema.parse(data)
}

export interface RateSample {
  at: number
  inBps: number
  outBps: number
  otherBps: number
  packetsPerSecond: number
}

// The server keeps the last fifteen minutes of per-second throughput, so the
// chart is full the moment a page opens and survives navigating away.
export function useTraffic(): {
  view: TrafficView | undefined
  samples: RateSample[]
  error: boolean
} {
  const query = useQuery({
    queryKey: QUERY_KEYS.TRAFFIC,
    queryFn: getTraffic,
    refetchInterval: 2000,
    retry: QUERY_CONFIG.RETRY.NONE,
  })
  const samples = useMemo(
    () =>
      (query.data?.history ?? []).map((point) => ({
        at: point.t_ms,
        inBps: point.in_bytes * 8,
        outBps: point.out_bytes * 8,
        otherBps: point.other_bytes * 8,
        packetsPerSecond: point.packets,
      })),
    [query.data]
  )
  return { view: query.data, samples, error: query.isError }
}

export type HostRole = 'clients' | 'servers' | 'all'

async function getCapture(): Promise<CaptureView> {
  const { data } = await apiClient.get(API_ENDPOINTS.CAPTURE)
  return captureViewSchema.parse(data)
}

// How the capture is set up and how well it is reading: drops, shed
// conversations and the share of handshakes that ended unread.
export function useCapture(): UseQueryResult<CaptureView> {
  return useQuery({
    queryKey: QUERY_KEYS.CAPTURE,
    queryFn: getCapture,
    refetchInterval: 3000,
    retry: QUERY_CONFIG.RETRY.NONE,
  })
}

async function getDns(): Promise<DnsView> {
  const { data } = await apiClient.get(API_ENDPOINTS.DNS, {
    params: { limit: 100 },
  })
  return dnsViewSchema.parse(data)
}

// Plain DNS the sensor has heard: which names are asked for, by whom, and
// which fail.
export function useDns(): UseQueryResult<DnsView> {
  return useQuery({
    queryKey: QUERY_KEYS.DNS,
    queryFn: getDns,
    refetchInterval: 3000,
    retry: QUERY_CONFIG.RETRY.NONE,
  })
}

async function getInterfaces(): Promise<InterfacesView> {
  const { data } = await apiClient.get(API_ENDPOINTS.INTERFACES)
  return interfacesViewSchema.parse(data)
}

export function useInterfaces(): UseQueryResult<InterfacesView> {
  return useQuery({
    queryKey: QUERY_KEYS.INTERFACES,
    queryFn: getInterfaces,
    staleTime: 30_000,
    retry: QUERY_CONFIG.RETRY.NONE,
  })
}

async function getObserved(): Promise<Observed> {
  const { data } = await apiClient.get(API_ENDPOINTS.OBSERVED)
  return observedSchema.parse(data)
}

// The client fingerprints this sensor has seen, and how much the feed can name.
export function useObserved(): UseQueryResult<Observed> {
  return useQuery({
    queryKey: QUERY_KEYS.OBSERVED,
    queryFn: getObserved,
    refetchInterval: 15_000,
  })
}

async function getHosts(role: HostRole): Promise<HostSummary[]> {
  const { data } = await apiClient.get(API_ENDPOINTS.HOSTS, {
    params: { limit: 500, role },
  })
  return hostSummarySchema.array().parse(data)
}

async function getHost(ip: string): Promise<HostProfile> {
  const { data } = await apiClient.get(
    `${API_ENDPOINTS.HOSTS}/${encodeURIComponent(ip)}`
  )
  return hostProfileSchema.parse(data)
}

// The addresses detection has observed, most recently active first. By default
// only machines that originated traffic: a server answering a ClientHello is
// seen too, but is not a host being watched.
export function useHosts(
  role: HostRole = 'clients'
): UseQueryResult<HostSummary[]> {
  return useQuery({
    queryKey: [...QUERY_KEYS.HOSTS, role],
    queryFn: () => getHosts(role),
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
  })
}

export function useHost(ip: string | null): UseQueryResult<HostProfile> {
  return useQuery({
    queryKey: QUERY_KEYS.HOST(ip ?? ''),
    queryFn: () => getHost(ip ?? ''),
    enabled: ip !== null,
    refetchInterval: QUERY_CONFIG.STALE_TIME.FREQUENT,
    retry: QUERY_CONFIG.RETRY.NONE,
  })
}
