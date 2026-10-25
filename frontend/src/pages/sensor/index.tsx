/**
 * © Pranav Verma | 2026
 * index.tsx
 */

import { useState } from 'react'
import { useCapture, useInterfaces, useMeta } from '@/api/hooks'
import type { CaptureView, InterfacesView } from '@/api/types'
import { CropFrame } from '@/components'
import { API_BASE, API_ENDPOINTS } from '@/config'
import {
  type TextSize,
  type TimeMode,
  useTextSize,
  useTheme,
  useTimeMode,
  useUIStore,
} from '@/core/lib/shell.ui.store'
import styles from './sensor.module.scss'
import { commandFor, nameForCommand, quote } from './sensor-data'

function Copy({ text }: { text: string }): React.ReactElement {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className={styles.copy}
      onClick={() => {
        navigator.clipboard
          ?.writeText(text)
          .then(() => {
            setDone(true)
            setTimeout(() => setDone(false), 1200)
          })
          .catch(() => undefined)
      }}
    >
      {done ? 'copied' : 'copy'}
    </button>
  )
}

function Choice<T extends string>({
  label,
  note,
  value,
  options,
  onChange,
}: {
  label: string
  note: string
  value: T
  options: { id: T; label: string }[]
  onChange: (value: T) => void
}): React.ReactElement {
  return (
    <div className={styles.pref}>
      <div className={styles.prefText}>
        <span className={styles.prefLabel}>{label}</span>
        <span className={styles.prefNote}>{note}</span>
      </div>
      <fieldset className={styles.seg}>
        <legend className={styles.legend}>{label}</legend>
        {options.map((option) => (
          <button
            key={option.id}
            type="button"
            aria-pressed={value === option.id}
            data-on={value === option.id || undefined}
            className={styles.segBtn}
            onClick={() => onChange(option.id)}
          >
            {option.label}
          </button>
        ))}
      </fieldset>
    </div>
  )
}

function Preferences(): React.ReactElement {
  const theme = useTheme()
  const timeMode = useTimeMode()
  const textSize = useTextSize()
  const setTheme = useUIStore((s) => s.setTheme)
  const setTimeMode = useUIStore((s) => s.setTimeMode)
  const setTextSize = useUIStore((s) => s.setTextSize)
  return (
    <CropFrame label="display" aside="saved in this browser only">
      <div className={styles.prefs}>
        <Choice
          label="theme"
          note="Dark suits a darkened room; system follows the operating system."
          value={theme}
          options={[
            { id: 'dark', label: 'dark' },
            { id: 'light', label: 'light' },
            { id: 'system', label: 'system' },
          ]}
          onChange={setTheme}
        />
        <Choice<TimeMode>
          label="times"
          note="The clock shown on events, lookups and profiles."
          value={timeMode}
          options={[
            { id: 'local', label: 'this computer' },
            { id: 'utc', label: 'utc' },
          ]}
          onChange={setTimeMode}
        />
        <Choice<TextSize>
          label="text size"
          note="Scales the whole dashboard."
          value={textSize}
          options={[
            { id: 'small', label: 'small' },
            { id: 'normal', label: 'normal' },
            { id: 'large', label: 'large' },
          ]}
          onChange={setTextSize}
        />
      </div>
    </CropFrame>
  )
}

function CaptureCard({ view }: { view: CaptureView }): React.ReactElement {
  const rows: [string, string][] = [
    ['source', view.mode],
    ['interface', view.interface ?? 'none'],
    ['kernel filter', view.filter ?? 'none'],
    [
      'promiscuous',
      view.promiscuous === null ? 'n/a' : view.promiscuous ? 'on' : 'off',
    ],
    [
      'kernel buffer',
      view.buffer_mib === null ? 'n/a' : `${view.buffer_mib} MiB`,
    ],
    ['conversations', view.limits.max_flows.toLocaleString()],
    ['idle timeout', `${view.limits.idle_timeout_secs} s`],
    ['per-stream limit', `${view.limits.stream_limit_kib} KiB`],
  ]
  return (
    <CropFrame label="capture" aside={`status: ${view.status}`}>
      <dl className={styles.facts}>
        {rows.map(([label, value]) => (
          <div key={label} className={styles.fact}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      <p className={styles.note}>
        These are fixed when the server starts. To change one, restart it with the
        flag shown under “change it” below; the dashboard cannot change what a
        running sensor captures.
      </p>
    </CropFrame>
  )
}

function Interfaces({ view }: { view: InterfacesView }): React.ReactElement {
  return (
    <CropFrame
      label="network interfaces"
      aside={view.available ? `${view.interfaces.length} found` : 'unavailable'}
    >
      {!view.available && (
        <p className={styles.note}>
          The capture library could not list interfaces: {view.reason}
        </p>
      )}
      <div className={styles.ifaces}>
        {view.interfaces.map((iface) => (
          <div key={iface.name} className={styles.iface} data-kind={iface.kind}>
            <div className={styles.ifaceHead}>
              <span className={styles.ifaceName} title={iface.name}>
                {iface.description ?? iface.name}
              </span>
              {iface.auto && <span className={styles.tag}>auto picks this</span>}
              {view.current === iface.name && (
                <span className={styles.tagOn}>capturing</span>
              )}
              <span className={styles.tagQuiet}>
                {iface.kind}
                {iface.up ? '' : ' · down'}
              </span>
            </div>
            <div className={styles.ifaceAddr}>
              {iface.addresses.length > 0
                ? iface.addresses.join('  ')
                : 'no address'}
            </div>
            <div className={styles.ifaceCmd}>
              <code>
                {commandFor(nameForCommand(iface.name, iface.description))}
              </code>
              <Copy
                text={commandFor(nameForCommand(iface.name, iface.description))}
              />
            </div>
          </div>
        ))}
      </div>
    </CropFrame>
  )
}

// Commands built from this sensor's real setup: the interface and filter it is
// using now, and an interface it could use instead. Anything the dashboard
// cannot know (a SIEM address) is a <placeholder>, not an invented value.
function recipesFor(
  capture: CaptureView | undefined,
  interfaces: InterfacesView | undefined
): { label: string; command: string }[] {
  const live = capture?.interface ?? 'auto'
  const base = `tlsfp serve --live ${quote(live)}`
  const other = interfaces?.interfaces.find(
    (i) =>
      i.kind === 'physical' &&
      i.up &&
      i.name !== capture?.interface &&
      i.addresses.length > 0
  )
  const recipes: { label: string; command: string }[] = []
  if (other) {
    recipes.push({
      label: `capture ${other.description ?? other.name} instead`,
      command: commandFor(nameForCommand(other.name, other.description)),
    })
  }
  recipes.push(
    {
      label: 'only HTTPS and QUIC, nothing else',
      command: `${base} --filter "tcp port 443 or udp port 443"`,
    },
    {
      label: `a busy link: bigger buffer than ${capture?.buffer_mib ?? 32} MiB and a bigger conversation table than ${(capture?.limits.max_flows ?? 65536).toLocaleString()}`,
      command: `${base} --buffer-mib 128 --max-flows 500000`,
    },
    {
      label: 'forward alerts to a SIEM',
      command: `${base} --alert-syslog udp://<siem-host>:514`,
    },
    {
      label: 'keep less history',
      command: `${base} --keep-days 14 --keep-alert-days 90`,
    }
  )
  return recipes
}

function Recipes({
  capture,
  interfaces,
}: {
  capture?: CaptureView
  interfaces?: InterfacesView
}): React.ReactElement {
  return (
    <CropFrame label="change it" aside="restart the server with the flag">
      <div className={styles.recipes}>
        {recipesFor(capture, interfaces).map((recipe) => (
          <div key={recipe.label} className={styles.recipe}>
            <span className={styles.recipeLabel}>{recipe.label}</span>
            <div className={styles.ifaceCmd}>
              <code>{recipe.command}</code>
              <Copy text={recipe.command} />
            </div>
          </div>
        ))}
      </div>
    </CropFrame>
  )
}

function Downloads(): React.ReactElement {
  const links: { label: string; note: string; href: string }[] = [
    {
      label: 'alerts (csv)',
      note: 'Every recorded alert.',
      href: `${API_BASE}${API_ENDPOINTS.EXPORT}?format=csv&limit=5000`,
    },
    {
      label: 'alerts (json)',
      note: 'The same, with every field.',
      href: `${API_BASE}${API_ENDPOINTS.EXPORT}?format=json&limit=5000`,
    },
    {
      label: 'conversations (json)',
      note: 'The Traffic table as the server holds it.',
      href: `${API_BASE}${API_ENDPOINTS.TRAFFIC}?limit=2000`,
    },
    {
      label: 'dns summary (json)',
      note: 'Names, clients and recent lookups.',
      href: `${API_BASE}${API_ENDPOINTS.DNS}?limit=200`,
    },
    {
      label: 'capture health (json)',
      note: 'Every counter the engine keeps.',
      href: `${API_BASE}${API_ENDPOINTS.CAPTURE}`,
    },
    {
      label: 'prometheus metrics',
      note: 'For Grafana and alert rules.',
      href: '/metrics',
    },
  ]
  return (
    <CropFrame label="data" aside="the same data the dashboard shows">
      <ul className={styles.links}>
        {links.map((link) => (
          <li key={link.href}>
            <a href={link.href} target="_blank" rel="noreferrer">
              {link.label}
            </a>
            <span>{link.note}</span>
          </li>
        ))}
      </ul>
    </CropFrame>
  )
}

const SHORTCUTS: [string, string][] = [
  ['/', 'focus the stream filter on Scope'],
  ['Esc', 'close the event drawer'],
  ['j / k', 'next and previous event in the drawer'],
]

export function Component(): React.ReactElement {
  const { data: capture } = useCapture()
  const { data: interfaces } = useInterfaces()
  const { data: meta } = useMeta()
  return (
    <div className={styles.page}>
      <section className={styles.masthead}>
        <span className={styles.over}>sensor</span>
        <h1 className={styles.title}>Sensor</h1>
        <p className={styles.sub}>
          How this sensor is set up, what it can capture from, how to change it,
          and how you want the dashboard to look.{' '}
          {meta && `tlsfp ${meta.version}.`}
        </p>
      </section>

      <div className={styles.cols}>
        <div className={styles.col}>
          {capture && <CaptureCard view={capture} />}
          {interfaces && <Interfaces view={interfaces} />}
        </div>
        <div className={styles.col}>
          <Preferences />
          <Recipes capture={capture} interfaces={interfaces} />
          <Downloads />
          <CropFrame label="keyboard">
            <dl className={styles.facts}>
              {SHORTCUTS.map(([key, what]) => (
                <div key={key} className={styles.fact}>
                  <dt>{key}</dt>
                  <dd>{what}</dd>
                </div>
              ))}
            </dl>
          </CropFrame>
        </div>
      </div>
    </div>
  )
}
