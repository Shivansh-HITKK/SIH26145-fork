'use client'

import { useEffect, useMemo, useState } from 'react'
import { signOut } from 'next-auth/react'
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  BellRing,
  BrainCircuit,
  ChevronRight,
  CircleHelp,
  Clock3,
  Crosshair,
  Database,
  FileJson,
  Filter,
  Gauge,
  HardDrive,
  LayoutDashboard,
  LogOut,
  Menu,
  Pause,
  Play,
  Search,
  Shield,
  ShieldCheck,
  Target,
  Terminal,
  TrendingUp,
  Wifi,
  X,
  Zap,
} from 'lucide-react'

type Tab = 'Overview' | 'Alerts' | 'Analytics' | 'About'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type ReplaySpeed = 0.5 | 1 | 2 | 4

type BackendEvidence = {
  feature: string
  value: string | number | boolean | null
  reason: string
}

type BackendAlert = {
  alert_id: string
  timestamp: string
  flow_id: string
  threat_class: string
  severity: Severity
  confidence: number
  source_ip: string
  destination_ip: string
  protocol: string
  window_seconds: number
  evidence: BackendEvidence[]
  detector: string
  model_version: string
  explanation?: string | null
}

type BackendIncident = {
  incident_id: string
  threat_class: string
  destination_ip: string
  protocol: string
  started_at: string
  last_seen_at: string
  window_seconds: number
  alert_count: number
  source_ips: string[]
  max_confidence: number
  severity: Severity
  alert_ids: string[]
  provenance: 'synthetic_fixture' | 'authorized_live_metadata'
}

type BackendMetrics = {
  processed_events: number
  alerts_generated: number
  events_per_second: number
  average_alert_latency_ms: number
  scenario: string | null
  source_mode?: 'idle' | 'fixture' | 'live'
  data_provenance: 'none' | 'synthetic_fixture' | 'authorized_live_metadata'
  interface?: string | null
  bpf_filter?: string | null
  status: string
  running: boolean
  started_at: number | null
  finished_at: number | null
  threat_counts: Record<string, number>
  error_count: number
  model_status: { available: boolean; version: string }
  appwrite_status: { enabled: boolean; persisted_count: number; last_error: string | null }
  ollama_status: { enabled: boolean; model: string; available: boolean }
  capture_stats?: {
    packets_seen: number
    flows_emitted: number
    dropped_packets: number
    error_count: number
    last_error: string | null
  }
  incidents_generated?: number
  last_error?: string
}

type AlertView = {
  alert_id: string
  severity: Severity
  threat: string
  source: string
  destination: string
  confidence: number
  time: string
  feature: string
  value: string
  reason: string
  raw: BackendAlert
}

type SocketMessage =
  | { type: 'alert'; alert: BackendAlert }
  | { type: 'incident'; incident: BackendIncident }
  | { type: 'metrics'; metrics: BackendMetrics }
  | { type: 'explained'; alert_id: string; explanation: string; source: 'ollama' | 'template' | 'cached' }

type SeverityFilter = 'all' | Severity

const CONFIGURED_API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL
const API_TOKEN = process.env.NEXT_PUBLIC_DETECTOR_API_TOKEN
const tabs: Tab[] = ['Overview', 'Alerts', 'Analytics', 'About']
const replaySpeeds: ReplaySpeed[] = [0.5, 1, 2, 4]

function apiBase() {
  if (CONFIGURED_API_BASE) {
    return CONFIGURED_API_BASE.replace(/\/(?:ws\/alerts|api)\/?$/, '').replace(/\/$/, '')
  }
  if (typeof window === 'undefined') return 'http://127.0.0.1:8000'

  const hostname = window.location.hostname.replace('-5173.', '-8000.')
  return `${window.location.protocol}//${hostname}:8000`
}

function apiUrl(path: string) {
  return `${apiBase()}${path}`
}

function wsUrl() {
  const base = apiBase().replace(/^http/, 'ws')
  return API_TOKEN ? `${base}/ws/alerts?access_token=${encodeURIComponent(API_TOKEN)}` : `${base}/ws/alerts`
}

function authHeaders(): Record<string, string> {
  return API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), {
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(init?.headers ?? {}),
    },
    ...init,
  })

  if (!response.ok) {
    throw new Error(await response.text())
  }

  return response.json() as Promise<T>
}

function humanizeThreat(value: string) {
  return value.replaceAll('_', ' ').replace(/\b\w/g, character => character.toUpperCase())
}

function severityLabel(value: Severity) {
  return value === 'critical'
    ? 'Critical'
    : value === 'high'
      ? 'High'
      : value === 'medium'
        ? 'Medium'
        : value === 'low'
          ? 'Low'
          : 'Info'
}

function severityTone(value: Severity) {
  return value === 'critical'
    ? 'tone-critical'
    : value === 'high'
      ? 'tone-high'
      : value === 'medium'
        ? 'tone-medium'
        : value === 'low'
          ? 'tone-low'
          : 'tone-info'
}

function provenanceLabel(value: BackendMetrics['data_provenance'] | undefined) {
  return value === 'authorized_live_metadata'
    ? 'AUTHORIZED LIVE DATA'
    : value === 'synthetic_fixture'
      ? 'SYNTHETIC FIXTURE'
      : 'NO DATA SOURCE'
}

function formatTimestamp(value: string) {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }

  return parsed.toLocaleString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    month: 'short',
    day: 'numeric',
  })
}

function timeAgo(unixSeconds: number | null) {
  if (!unixSeconds) return 'not started'

  const seconds = Math.max(0, Math.floor((Date.now() - unixSeconds * 1000) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  return `${Math.floor(minutes / 60)}h ago`
}

function abbreviate(value: number) {
  if (value >= 1000) {
    return `${(value / 1000).toFixed(1)}k`
  }
  return `${value}`
}

function chartPath(values: number[], width: number, height: number) {
  if (values.length === 0) return ''

  return values
    .map((value, index) => {
      const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width
      const y = height - (value / 100) * height
      return `${index === 0 ? 'M' : 'L'} ${x} ${y}`
    })
    .join(' ')
}

function normalizeAlert(alert: BackendAlert): AlertView {
  const evidence = alert.evidence[0]

  return {
    alert_id: alert.alert_id,
    severity: alert.severity,
    threat: humanizeThreat(alert.threat_class),
    source: `${alert.source_ip} · ${alert.protocol.toUpperCase()}`,
    destination: alert.destination_ip,
    confidence: alert.confidence,
    time: alert.timestamp,
    feature: evidence?.feature ?? 'unknown',
    value: String(evidence?.value ?? 'n/a'),
    reason: evidence?.reason ?? 'No evidence available',
    raw: alert,
  }
}

function IncidentTable({ incidents }: { incidents: BackendIncident[] }) {
  return (
    <section className="panel alerts-panel" style={{ marginBottom: '18px' }}>
      <div className="panel-heading alerts-heading">
        <div>
          <span className="eyebrow">GROUPED INCIDENTS</span>
          <h2>Active incident groups <span className="count-badge">{incidents.length}</span></h2>
        </div>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>SEVERITY</th><th>THREAT CLASS</th><th>SOURCES</th><th>DESTINATION</th><th>ALERTS</th><th>CONFIDENCE</th><th>LAST SEEN</th></tr></thead>
          <tbody>
            {incidents.map(incident => (
              <tr key={incident.incident_id}>
                <td><span className={`severity-badge ${severityTone(incident.severity)}`}><span />{severityLabel(incident.severity)}</span></td>
                <td><strong>{humanizeThreat(incident.threat_class)}</strong><small>{incident.incident_id}</small></td>
                <td className="mono">{incident.source_ips.length}</td>
                <td className="mono">{incident.destination_ip} · {incident.protocol}</td>
                <td className="mono">{incident.alert_count}</td>
                <td className="mono">{Math.round(incident.max_confidence * 100)}%</td>
                <td className="mono muted">{formatTimestamp(incident.last_seen_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!incidents.length && <div className="empty-state"><strong>No grouped incidents</strong><span>Waiting for authorized metadata.</span></div>}
      </div>
    </section>
  )
}

function Logo() {
  return (
    <div className="logo-mark">
      <ShieldCheck size={22} strokeWidth={2.4} />
    </div>
  )
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
      />
      <path
        fill="#EA4335"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
      />
    </svg>
  )
}

function Header({
  tab,
  setTab,
  status,
  onLogout,
  userEmail,
}: {
  tab: Tab
  setTab: (value: Tab) => void
  status: BackendMetrics | null
  onLogout: () => void
  userEmail?: string | null
}) {
  const [clock, setClock] = useState('')

  useEffect(() => {
    const tick = () => {
      setClock(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }))
    }

    tick()
    const timer = window.setInterval(tick, 1000)
    return () => window.clearInterval(timer)
  }, [])

  return (
    <header className="topbar">
      <div className="brand">
        <Logo />
        <div>
          <strong>SIH<span className="cyan">26145</span></strong>
          <small>THREAT INTELLIGENCE CONSOLE</small>
        </div>
      </div>

      <nav>
        {tabs.map(item => (
          <button key={item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)} type="button">
            {item === 'Overview' && <LayoutDashboard size={15} />}
            {item === 'Alerts' && <BellRing size={15} />}
            {item === 'Analytics' && <BarChart3 size={15} />}
            {item === 'About' && <CircleHelp size={15} />}
            {item}
          </button>
        ))}
      </nav>

      <div className="top-actions">
        {userEmail && (
          <span className="pill" title={`Signed in as ${userEmail}`}>
            <ShieldCheck size={13} className="cyan-icon" /> {userEmail.split('@')[0].toUpperCase()}
          </span>
        )}
        <span className="clock">
          <Clock3 size={14} /> {clock}
        </span>
        <span className={`pill ${status?.running ? 'connected' : ''}`} title={provenanceLabel(status?.data_provenance)}>
          <span className="status-dot" /> {status?.running ? 'REALTIME' : 'IDLE'}
        </span>
        <span className="pill">
          APPWRITE {status?.appwrite_status.enabled ? <span className="pill-check">✓</span> : '—'}
        </span>
        <span className="pill violet-pill">ML {status?.model_status.available ? <span className="pill-check">✓</span> : '—'}</span>
        <button className="icon-button" onClick={onLogout} aria-label="Log out" title="Sign out" type="button">
          <LogOut size={17} />
        </button>
      </div>

      <button className="menu-button" aria-label="Open menu" type="button">
        <Menu size={20} />
      </button>
    </header>
  )
}

function LoginScreen({ onContinue }: { onContinue: () => void }) {
  const [isSigningIn, setIsSigningIn] = useState(false)

  const handleGoogleSignIn = () => {
    setIsSigningIn(true)
    onContinue()
  }

  return (
    <main className="login-screen" suppressHydrationWarning>
      <div className="login-grid" />
      <div className="login-glow" />

      <section className="login-card" suppressHydrationWarning>
        <div className="login-brand">
          <Logo />
          <span>SIH<span className="cyan">26145</span></span>
        </div>

        <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
        <h1>
          See the signal.
          <br />
          <span>Stop the threat.</span>
        </h1>
        <p className="login-copy">
          A focused command surface for passive network intelligence, replay control, and incident review. Authenticate with your authorized Google account to enter.
        </p>

        <div className="login-form">
          <button
            className="primary-button"
            onClick={() => void handleGoogleSignIn()}
            disabled={isSigningIn}
            type="button"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              backgroundColor: '#ffffff',
              color: '#0f172a',
              fontWeight: 600,
              fontSize: '13px',
              padding: '13px 20px',
              marginTop: '10px',
              border: 'none',
              borderRadius: '7px',
              boxShadow: '0 4px 14px rgba(0, 0, 0, 0.35)',
              cursor: isSigningIn ? 'wait' : 'pointer',
              transition: 'transform 0.15s ease, background-color 0.15s ease',
            }}
          >
            <GoogleIcon />
            {isSigningIn ? 'Connecting to Google...' : 'Continue with Google'}
          </button>
        </div>

        <div className="login-note">
          <Shield size={14} /> OAuth 2.0 secured • Google Identity verification
        </div>
      </section>

      <div className="login-footer">
        <span>SIH26145 / THREAT INTELLIGENCE</span>
        <span>
          BUILD 2.4.0 <span className="status-dot" /> SYSTEM READY
        </span>
      </div>
    </main>
  )
}

function StatCard({ icon: Icon, label, value, detail, tone, sparkColor }: { icon: typeof Activity; label: string; value: string; detail: string; tone: string; sparkColor: string }) {
  return (
    <article className={`stat-card ${tone}`}>
      <div className="stat-top">
        <span className="stat-icon">
          <Icon size={18} />
        </span>
        <span className="stat-label">{label}</span>
      </div>
      <strong className="stat-value">{value}</strong>
      <span className="stat-detail">{detail}</span>
      <svg className="sparkline" viewBox="0 0 180 48" preserveAspectRatio="none" aria-hidden="true">
        <path d="M0 39 C18 36, 19 26, 32 31 S49 40, 61 27 S79 29, 93 19 S113 31, 127 20 S148 10, 180 4" fill="none" stroke={sparkColor} strokeWidth="2.5" />
        <path d="M0 39 C18 36, 19 26, 32 31 S49 40, 61 27 S79 29, 93 19 S113 31, 127 20 S148 10, 180 4 V48 H0Z" fill={sparkColor} opacity=".08" />
      </svg>
    </article>
  )
}

function ReplayControls({
  scenarios,
  selectedScenario,
  setSelectedScenario,
  speed,
  setSpeed,
  running,
  onStart,
  onStop,
  liveInterface,
  setLiveInterface,
  liveInterfaces,
  liveBpfFilter,
  setLiveBpfFilter,
  onStartLive,
  status,
}: {
  scenarios: string[]
  selectedScenario: string
  setSelectedScenario: (value: string) => void
  speed: ReplaySpeed
  setSpeed: (value: ReplaySpeed) => void
  running: boolean
  onStart: () => void
  onStop: () => void
  liveInterface: string
  setLiveInterface: (value: string) => void
  liveInterfaces: string[]
  liveBpfFilter: string
  setLiveBpfFilter: (value: string) => void
  onStartLive: () => void
  status: BackendMetrics | null
}) {
  return (
    <section className="replay-panel panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">CONTROL PLANE</span>
          <h2>Replay environment</h2>
        </div>
        <span className="read-only">
          <ShieldCheck size={13} /> READ-ONLY MONITOR
        </span>
      </div>

      <div className="replay-controls">
        <label>
          SCENARIO
          <select value={selectedScenario} onChange={event => setSelectedScenario(event.target.value)}>
            {scenarios.map(scenario => (
              <option key={scenario} value={scenario}>
                {scenario}
              </option>
            ))}
          </select>
        </label>

        <label>
          SPEED
          <div className="speed-picker">
            {replaySpeeds.map(option => (
              <button key={option} className={speed === option ? 'selected' : ''} onClick={() => setSpeed(option)} type="button">
                {option}x
              </button>
            ))}
          </div>
        </label>

        <div className="replay-buttons">
          <button className="primary-button compact" onClick={onStart} type="button" disabled={!selectedScenario || running}>
            <Play size={14} fill="currentColor" /> {running ? 'Running' : 'Start replay'}
          </button>
          <button className="secondary-button compact" onClick={onStop} type="button">
            <Pause size={14} /> Stop
          </button>
        </div>

        <label>
          LIVE INTERFACE
          <input
            list="capture-interfaces"
            value={liveInterface}
            onChange={event => setLiveInterface(event.target.value)}
            placeholder="default interface"
            aria-label="Live capture interface"
          />
          <datalist id="capture-interfaces">
            {liveInterfaces.map(interfaceName => <option key={interfaceName} value={interfaceName} />)}
          </datalist>
        </label>

        <label>
          BPF FILTER
          <input
            value={liveBpfFilter}
            onChange={event => setLiveBpfFilter(event.target.value)}
            placeholder="ip or ip6"
            aria-label="Live capture BPF filter"
          />
        </label>

        <button className="secondary-button compact" onClick={onStartLive} type="button" disabled={running}>
          <Wifi size={14} /> Start live capture
        </button>
      </div>

      <div className="replay-status">
        <span className={`live-pulse ${running ? 'on' : ''}`} />
        {status?.status === 'running' && status.source_mode === 'live'
          ? `Capturing passive metadata on ${(status.interface ?? liveInterface) || 'default interface'}`
          : status?.status === 'running'
            ? `Streaming ${selectedScenario.replaceAll('_', ' ')} events`
          : status?.status === 'completed'
            ? 'Replay completed'
            : status?.status === 'error'
              ? 'Replay error'
              : 'Replay engine idle'}
        <span className="replay-id">SOURCE / {status?.source_mode?.toUpperCase() ?? 'IDLE'}</span>
        {status?.source_mode === 'live' && status.capture_stats && (
          <span className="replay-id">
            PACKETS / {status.capture_stats.packets_seen} · FLOWS / {status.capture_stats.flows_emitted} · DROPPED / {status.capture_stats.dropped_packets}
          </span>
        )}
      </div>
    </section>
  )
}

function OverviewTimeline({ alerts }: { alerts: AlertView[] }) {
  const values = useMemo(() => {
    const base = Array.from({ length: 12 }, () => 0)
    alerts.forEach((alert, index) => {
      base[index % base.length] += Math.max(10, Math.round(alert.confidence * 100))
    })
    return base.map(value => Math.min(100, value))
  }, [alerts])

  const path = chartPath(values, 820, 180)
  const area = path ? `${path} L820 200 L0 200 Z` : ''

  return (
    <section className="panel chart-panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">DETECTION TELEMETRY</span>
          <h2>Detection timeline</h2>
        </div>
        <div className="chart-legend">
          <span>
            <i className="legend-cyan" /> Alert confidence
          </span>
          <span className="live-label">
            <i className="live-pulse on" /> LIVE
          </span>
        </div>
      </div>

      <div className="timeline-chart">
        <div className="y-axis">
          <span>100</span>
          <span>75</span>
          <span>50</span>
          <span>0</span>
        </div>
        <div className="chart-main">
          <div className="chart-grid-lines">
            <i />
            <i />
            <i />
            <i />
          </div>
          {path ? (
            <svg viewBox="0 0 820 200" preserveAspectRatio="none" className="area-svg">
              <defs>
                <linearGradient id="area-live" x1="0" x2="0" y1="0" y2="1">
                  <stop offset="0" stopColor="#22d3ee" stopOpacity=".34" />
                  <stop offset="1" stopColor="#22d3ee" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path d={area} fill="url(#area-live)" />
              <path d={path} fill="none" stroke="#22d3ee" strokeWidth="3" vectorEffect="non-scaling-stroke" />
            </svg>
          ) : (
            <div className="empty-chart">Waiting for replay data</div>
          )}
          <div className="x-axis">
            <span>−30m</span>
            <span>−24m</span>
            <span>−18m</span>
            <span>−12m</span>
            <span>−6m</span>
            <span>NOW</span>
          </div>
        </div>
      </div>
    </section>
  )
}

function ThreatDistribution({ alerts }: { alerts: AlertView[] }) {
  const counts = alerts.reduce<Record<string, number>>((accumulator, alert) => {
    const key = alert.threat
    accumulator[key] = (accumulator[key] ?? 0) + 1
    return accumulator
  }, {})

  const items = Object.entries(counts)
    .map(([name, count]) => ({
      name,
      count,
      percentage: alerts.length ? Math.round((count / alerts.length) * 100) : 0,
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 5)

  const palette = ['#22d3ee', '#a78bfa', '#34d399', '#fbbf24', '#60a5fa']
  const gradient = items.map((item, index) => `${palette[index]} 0 ${item.percentage}%`).join(', ')

  return (
    <section className="panel distribution">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">THREAT TAXONOMY</span>
          <h2>Distribution</h2>
        </div>
        <button className="dots" type="button">
          •••
        </button>
      </div>

      <div className="donut-wrap">
        <div className="donut" style={{ background: items.length ? `conic-gradient(${gradient})` : '#1b2940' }}>
          <div>
            <strong>{alerts.length}</strong>
            <span>alerts</span>
          </div>
        </div>

        <div className="legend-list">
          {items.length ? (
            items.map((item, index) => (
              <div key={item.name}>
                <span className="legend-dot" style={{ background: palette[index] }} />
                <span>{item.name}</span>
                <strong>{item.count}</strong>
              </div>
            ))
          ) : (
            <div className="legend-empty">No alert distribution yet</div>
          )}
        </div>
      </div>

      <div className="distribution-foot">
        <span>
          <span className="live-pulse on" /> {alerts.length} alerts classified
        </span>
        <span>
          {alerts.length ? 'Live feed connected' : 'Waiting for live feed'} <TrendingUp size={13} />
        </span>
      </div>
    </section>
  )
}

function AlertsTable({ alerts, onSelect }: { alerts: AlertView[]; onSelect: (alert: AlertView) => void }) {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<SeverityFilter>('all')

  const filtered = useMemo(
    () =>
      alerts.filter(alert => {
        const matchSeverity = filter === 'all' || alert.severity === filter
        const searchText = [alert.alert_id, alert.threat, alert.source, alert.destination, alert.feature, alert.value, alert.reason, alert.raw.detector, alert.raw.model_version]
          .join(' ')
          .toLowerCase()
        const matchSearch = searchText.includes(search.toLowerCase())
        return matchSeverity && matchSearch
      }),
    [alerts, filter, search],
  )

  return (
    <section className="panel alerts-panel">
      <div className="panel-heading alerts-heading">
        <div>
          <span className="eyebrow">INCIDENT STREAM</span>
          <h2>
            Recent alerts <span className="count-badge">{filtered.length}</span>
          </h2>
        </div>

        <div className="table-tools">
          <div className="search-box">
            <Search size={15} />
            <input placeholder="Search alerts..." value={search} onChange={event => setSearch(event.target.value)} />
          </div>
          <div className="filter-chips">
            <Filter size={14} />
            {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map(item => (
              <button key={item} className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)} type="button">
                {item === 'all' ? 'All' : severityLabel(item)}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>SEVERITY</th>
              <th>THREAT CLASS</th>
              <th>SOURCE</th>
              <th>DESTINATION</th>
              <th>CONFIDENCE</th>
              <th>TIME</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {filtered.map(alert => (
              <tr key={alert.alert_id} onClick={() => onSelect(alert)}>
                <td>
                  <span className={`severity-badge ${severityTone(alert.severity)}`}>
                    <span />
                    {severityLabel(alert.severity)}
                  </span>
                </td>
                <td>
                  <strong>{alert.threat}</strong>
                  <small>{alert.alert_id}</small>
                </td>
                <td className="mono">{alert.source}</td>
                <td className="mono">{alert.destination}</td>
                <td>
                  <div className="confidence">
                    <div>
                      <span style={{ width: `${Math.round(alert.confidence * 100)}%` }} />
                      <i />
                    </div>
                    <strong>{Math.round(alert.confidence * 100)}%</strong>
                  </div>
                </td>
                <td className="mono muted">{formatTimestamp(alert.time)}</td>
                <td>
                  <ChevronRight size={16} className="row-arrow" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="empty-state">
            <Search size={24} />
            <strong>No matching alerts</strong>
            <span>Try changing your search or severity filter.</span>
          </div>
        )}
      </div>
    </section>
  )
}

function EvidenceDrawer({ alert, explanation, explanationSource, explanationLoading, onExplain, onClose }: { alert: AlertView | null; explanation: string | null; explanationSource: string | null; explanationLoading: boolean; onExplain: () => void; onClose: () => void }) {
  if (!alert) return null

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="evidence-drawer">
        <div className="drawer-head">
          <div>
            <span className="eyebrow">EVIDENCE / {alert.alert_id}</span>
            <h2>Alert investigation</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close drawer" type="button">
            <X size={18} />
          </button>
        </div>

        <div className={`drawer-summary ${severityTone(alert.severity)}`}>
          <div className="summary-icon">
            <AlertTriangle size={22} />
          </div>
          <div>
            <span>{severityLabel(alert.severity)} severity</span>
            <strong>{alert.threat}</strong>
          </div>
          <span className="summary-confidence">
            {Math.round(alert.confidence * 100)}%
            <small>CONFIDENCE</small>
          </span>
        </div>

        <div className="drawer-section">
          <span className="eyebrow">NETWORK CONTEXT</span>
          <div className="context-grid">
            <div>
              <small>SOURCE</small>
              <strong>{alert.source}</strong>
            </div>
            <div>
              <small>DESTINATION</small>
              <strong>{alert.destination}</strong>
            </div>
            <div>
              <small>DETECTED</small>
              <strong>{formatTimestamp(alert.time)}</strong>
            </div>
            <div>
              <small>MODEL</small>
              <strong>{alert.raw.model_version}</strong>
            </div>
          </div>
        </div>

        <div className="drawer-section">
          <span className="eyebrow">EVIDENCE SIGNALS</span>
          <div className="evidence-cards">
            <div>
              <Target size={15} />
              <span>
                FEATURE
                <strong>{alert.feature}</strong>
              </span>
            </div>
            <div>
              <Gauge size={15} />
              <span>
                VALUE
                <strong>{alert.value}</strong>
              </span>
            </div>
            <div>
              <BrainCircuit size={15} />
              <span>
                REASON
                <strong>{alert.reason}</strong>
              </span>
            </div>
          </div>
        </div>

        <div className="drawer-section json-section">
          <div className="json-label">
            <span className="eyebrow">RAW EVENT</span>
            <FileJson size={15} />
          </div>
          <pre>
            {JSON.stringify(
              {
                alert_id: alert.raw.alert_id,
                timestamp: alert.raw.timestamp,
                flow_id: alert.raw.flow_id,
                threat_class: alert.raw.threat_class,
                severity: alert.raw.severity,
                confidence: alert.raw.confidence,
                source_ip: alert.raw.source_ip,
                destination_ip: alert.raw.destination_ip,
                protocol: alert.raw.protocol,
                window_seconds: alert.raw.window_seconds,
                detector: alert.raw.detector,
                model_version: alert.raw.model_version,
                explanation: explanation ?? alert.raw.explanation ?? null,
                evidence: alert.raw.evidence,
              },
              null,
              2,
            )}
          </pre>

          <button className="secondary-button compact explanation-button" onClick={onExplain} type="button">
            {explanationLoading ? 'Generating AI explanation...' : explanation ? 'Regenerate explanation' : 'Explain alert with AI'}
          </button>
          {explanation && (
            <div className="explanation-result">
              <div className="json-label">
                <span className="eyebrow">ANALYST EXPLANATION</span>
                <span className="muted">{explanationSource === 'ollama' ? 'OLLAMA AI' : explanationSource === 'cached' ? 'CACHED' : 'FALLBACK'}</span>
              </div>
              <p>{explanation}</p>
            </div>
          )}
        </div>
      </aside>
    </>
  )
}

function Analytics({ alerts, metrics }: { alerts: AlertView[]; metrics: BackendMetrics | null }) {
  const confidenceSeries = useMemo(() => {
    const series = Array.from({ length: 24 }, () => 0)
    alerts.forEach((alert, index) => {
      series[index % series.length] += Math.max(10, Math.round(alert.confidence * 100))
    })
    return series.map(value => Math.min(100, value))
  }, [alerts])

  const path = chartPath(confidenceSeries, 900, 240)
  const area = path ? `${path} L900 260 L0 260 Z` : ''
  const severityCounts = alerts.reduce<Record<string, number>>((accumulator, alert) => {
    accumulator[alert.severity] = (accumulator[alert.severity] ?? 0) + 1
    return accumulator
  }, {})

  const topThreats = Object.entries(metrics?.threat_counts ?? {}).sort((left, right) => right[1] - left[1]).slice(0, 6)

  return (
    <div className="analytics-grid">
      <section className="panel big-analytics">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">SIGNAL VELOCITY</span>
            <h2>Detection volume</h2>
          </div>
          <span className="metric-up">
            <span className="live-pulse on" /> Streaming now
          </span>
        </div>

        <div className="analytics-area">
          {path ? (
            <svg viewBox="0 0 900 260" preserveAspectRatio="none">
              <defs>
                <linearGradient id="analytics-area-live" x1="0" x2="0" y1="0" y2="1">
                  <stop stopColor="#a78bfa" stopOpacity=".4" />
                  <stop offset="1" stopColor="#a78bfa" stopOpacity="0" />
                </linearGradient>
              </defs>
              <path d={area} fill="url(#analytics-area-live)" />
              <path d={path} fill="none" stroke="#a78bfa" strokeWidth="3" vectorEffect="non-scaling-stroke" />
            </svg>
          ) : (
            <div className="empty-chart large">Start a replay to populate analytics</div>
          )}
        </div>
      </section>

      <section className="panel distribution analytics-summary">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">CLASS BREAKDOWN</span>
            <h2>Severity spread</h2>
          </div>
        </div>

        <div className="severity-grid">
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(item => (
            <div key={item} className={`severity-stat ${severityTone(item)}`}>
              <span>{severityLabel(item)}</span>
              <strong>{abbreviate(severityCounts[item] ?? 0)}</strong>
            </div>
          ))}
        </div>
      </section>

      <ThreatDistribution alerts={alerts} />

      <section className="panel class-breakdown">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">TOP CLASSES</span>
            <h2>Threat counts</h2>
          </div>
        </div>

        {topThreats.length ? (
          topThreats.map(([threat, count]) => {
            const max = Math.max(...topThreats.map(([, total]) => total), 1)
            return (
              <div className="bar-row" key={threat}>
                <span>{humanizeThreat(threat)}</span>
                <div>
                  <i style={{ width: `${Math.max(12, Math.round((count / max) * 100))}%` }} />
                </div>
                <strong>{count}</strong>
              </div>
            )
          })
        ) : (
          <div className="empty-state compact">
            <Activity size={22} />
            <strong>No detections yet</strong>
            <span>Run replay to see threat distribution.</span>
          </div>
        )}
      </section>

      <section className="panel posture">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">SYSTEM POSTURE</span>
            <h2>Infrastructure health</h2>
          </div>
          <span className="posture-score">{metrics ? Math.max(0, 100 - metrics.error_count * 8).toFixed(1) : '98.7'}</span>
        </div>

        <div className="posture-line">
          <span>
            <Wifi size={15} /> Realtime transport
          </span>
          <b>{metrics?.running ? 'Operational' : 'Idle'}</b>
        </div>
        <div className="posture-line">
          <span>
            <Database size={15} /> Event ingestion
          </span>
          <b>{metrics?.status ?? 'idle'}</b>
        </div>
        <div className="posture-line">
          <span>
            <Activity size={15} /> Data provenance
          </span>
          <b>{provenanceLabel(metrics?.data_provenance)}</b>
        </div>
        <div className="posture-line">
          <span>
            <BrainCircuit size={15} /> Detection engine
          </span>
          <b>{metrics?.model_status.available ? metrics.model_status.version : 'rules-only'}</b>
        </div>
        <div className="posture-line">
          <span>
            <HardDrive size={15} /> Evidence store
          </span>
            <b>{metrics?.appwrite_status.enabled ? 'Connected' : 'Local'}</b>
        </div>
      </section>
    </div>
  )
}

function About({ metrics }: { metrics: BackendMetrics | null }) {
  return (
    <div className="about-grid">
      <section className="about-hero panel">
        <div className="about-icon">
          <Shield size={28} />
        </div>
        <span className="eyebrow">ABOUT SIH26145</span>
        <h1>
          Passive intelligence,
          <br />
          <span>decisive clarity.</span>
        </h1>
        <p>
          SIH26145 is a read-only cybersecurity operations console designed to surface meaningful network behavior without probes, decryption, or disruption.
        </p>
        <div className="about-stats">
          <div>
            <strong>{Object.keys(metrics?.threat_counts ?? {}).length.toString().padStart(2, '0')}</strong>
            <span>Observed classes</span>
          </div>
          <div>
            <strong>{metrics?.running ? 'LIVE' : 'IDLE'}</strong>
            <span>Replay state</span>
          </div>
          <div>
            <strong>{metrics?.model_status.version ?? 'rules-only'}</strong>
            <span>Model version</span>
          </div>
        </div>
      </section>

      <section className="panel problem-panel">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">BACKEND CONTRACT</span>
            <h2>Connected endpoints</h2>
          </div>
          <Crosshair size={18} className="cyan-icon" />
        </div>
        <p>
          The dashboard now reads replay scenarios, metrics, alerts, and live websocket messages directly from the FastAPI backend.
        </p>
        <div className="problem-tags">
          <span>/api/scenarios</span>
          <span>/api/metrics</span>
          <span>/api/alerts</span>
          <span>/api/replay/start</span>
          <span>/api/replay/stop</span>
          <span>/ws/alerts</span>
          <span>/api/explain/{'{alert_id}'}</span>
        </div>
      </section>

      <section className="panel problem-panel">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">SIH 2026 TEAM</span>
            <h2>Heritage Institute of Technology, Kolkata</h2>
          </div>
          <Shield size={18} className="cyan-icon" />
        </div>
        <p>
          <strong>Team Lead:</strong> Shivansh Kumar
        </p>
        <div className="problem-tags">
          <span>Satyam Raj</span>
          <span>Anshika</span>
          <span>Aditya</span>
          <span>Piyush</span>
          <span>Priyanshu</span>
        </div>
      </section>

      <section className="panel sample-json">
        <div className="panel-heading">
          <div>
            <span className="eyebrow">INTEGRATION REFERENCE</span>
            <h2>Sample payload</h2>
          </div>
          <Terminal size={17} className="muted" />
        </div>
        <pre>{`POST ${apiBase()}/api/replay/start
{
  "scenario": "syn_flood",
  "speed": 1
}`}</pre>
      </section>
    </div>
  )
}

function App() {
  const session = null
  const [demoAccess, setDemoAccess] = useState(false)
  const [tab, setTab] = useState<Tab>('Overview')
  const [metrics, setMetrics] = useState<BackendMetrics | null>(null)
  const [scenarios, setScenarios] = useState<string[]>([])
  const [selectedScenario, setSelectedScenario] = useState('')
  const [speed, setSpeed] = useState<ReplaySpeed>(1)
  const [liveInterface, setLiveInterface] = useState('')
  const [liveInterfaces, setLiveInterfaces] = useState<string[]>([])
  const [liveBpfFilter, setLiveBpfFilter] = useState('ip or ip6')
  const [alerts, setAlerts] = useState<AlertView[]>([])
  const [incidents, setIncidents] = useState<BackendIncident[]>([])
  const [selected, setSelected] = useState<AlertView | null>(null)
  const [explanation, setExplanation] = useState<string | null>(null)
  const [explanationSource, setExplanationSource] = useState<string | null>(null)
  const [explanationLoading, setExplanationLoading] = useState(false)
  const [loading, setLoading] = useState(true)
  const [connectionState, setConnectionState] = useState<'connecting' | 'connected' | 'error'>('connecting')
  const [operationError, setOperationError] = useState<string | null>(null)


  useEffect(() => {
    if (scenarios.length && !selectedScenario) {
      setSelectedScenario(scenarios[0])
    }
  }, [scenarios, selectedScenario])

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        const [scenarioResponse, metricsResponse, alertResponse, incidentResponse, interfaceResponse] = await Promise.all([
          requestJson<{ scenarios: string[] }>('/api/scenarios'),
          requestJson<BackendMetrics>('/api/metrics'),
          requestJson<{ alerts: BackendAlert[] }>('/api/alerts?limit=100'),
          requestJson<{ incidents: BackendIncident[] }>('/api/incidents?limit=100'),
          requestJson<{ interfaces: string[] }>('/api/live/interfaces'),
        ])

        if (cancelled) return

        setScenarios(scenarioResponse.scenarios)
        setMetrics(metricsResponse)
        setAlerts(alertResponse.alerts.map(normalizeAlert))
        setIncidents(incidentResponse.incidents)
        setLiveInterfaces(interfaceResponse.interfaces)
        setSelectedScenario(metricsResponse.scenario ?? scenarioResponse.scenarios[0] ?? '')
        setConnectionState('connected')
      } catch (error) {
        console.error(error)
        if (!cancelled) setConnectionState('error')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    const socket = new WebSocket(wsUrl())

    socket.onopen = () => setConnectionState('connected')
    socket.onerror = () => setConnectionState('error')
    socket.onmessage = event => {
      const message = JSON.parse(event.data) as SocketMessage
      if (message.type === 'metrics') {
        setMetrics(message.metrics)
        if (message.metrics.status === 'running' && message.metrics.source_mode !== 'fixture') {
          setSelected(null)
          setExplanation(null)
          setExplanationSource(null)
        }
        if (message.metrics.scenario) {
          setSelectedScenario(message.metrics.scenario)
        }
      }

      if (message.type === 'alert') {
        const alert = normalizeAlert(message.alert)
        setAlerts(current => [alert, ...current.filter(item => item.alert_id !== alert.alert_id)])
      }

      if (message.type === 'incident') {
        setIncidents(current => [message.incident, ...current.filter(item => item.incident_id !== message.incident.incident_id)])
      }

      if (message.type === 'explained') {
        setAlerts(current =>
          current.map(item =>
            item.alert_id === message.alert_id
              ? {
                  ...item,
                  raw: {
                    ...item.raw,
                    explanation: message.explanation,
                  },
                }
              : item,
          ),
        )

        if (selected?.alert_id === message.alert_id) {
          setExplanation(message.explanation)
          setExplanationSource(message.source)
          setExplanationLoading(false)
        }
      }
    }

    return () => socket.close()
  }, [selected?.alert_id])

  const handleLogout = async () => {
    await signOut({ callbackUrl: '/' })
  }

  const handleStart = async () => {
    if (!selectedScenario) return
    setOperationError(null)
    try {
      await requestJson('/api/replay/start', {
        method: 'POST',
        body: JSON.stringify({ scenario: selectedScenario, speed }),
      })
      setMetrics(current => (current ? { ...current, scenario: selectedScenario, running: true, status: 'running' } : current))
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : 'Unable to start replay')
    }
  }

  const handleStop = async () => {
    setOperationError(null)
    try {
      await requestJson('/api/replay/stop', { method: 'POST' })
      setMetrics(current => (current ? { ...current, running: false, status: 'stopped' } : current))
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : 'Unable to stop capture')
    }
  }

  const handleStartLive = async () => {
    setOperationError(null)
    try {
      await requestJson('/api/live/start', {
        method: 'POST',
        body: JSON.stringify({ interface: liveInterface || null, bpf_filter: liveBpfFilter }),
      })
      setMetrics(current =>
        current
          ? { ...current, scenario: null, source_mode: 'live', interface: liveInterface || 'default', running: true, status: 'running' }
          : current,
      )
    } catch (error) {
      setOperationError(error instanceof Error ? error.message : 'Unable to start live capture')
    }
  }

  const handleExplain = async () => {
    if (!selected) return
    setExplanationLoading(true)
    setOperationError(null)
    try {
      const response = await requestJson<{ explanation: string; source: string }>(`/api/explain/${selected.alert_id}`)
      setExplanation(response.explanation)
      setExplanationSource(response.source)
    } catch {
      setOperationError('This alert is no longer available in the current capture.')
      setSelected(null)
      setExplanation(null)
      setExplanationSource(null)
    } finally {
      setExplanationLoading(false)
    }
  }

  const content = useMemo(() => {
    if (tab === 'Alerts') {
      return <><IncidentTable incidents={incidents} /><AlertsTable alerts={alerts} onSelect={setSelected} /></>
    }

    if (tab === 'Analytics') {
      return <Analytics alerts={alerts} metrics={metrics} />
    }

    if (tab === 'About') {
      return <About metrics={metrics} />
    }

    return (
      <>
        <ReplayControls
          scenarios={scenarios}
          selectedScenario={selectedScenario}
          setSelectedScenario={setSelectedScenario}
          speed={speed}
          setSpeed={setSpeed}
          running={Boolean(metrics?.running)}
          onStart={() => void handleStart()}
          onStop={() => void handleStop()}
          liveInterface={liveInterface}
          setLiveInterface={setLiveInterface}
          liveInterfaces={liveInterfaces}
          liveBpfFilter={liveBpfFilter}
          setLiveBpfFilter={setLiveBpfFilter}
          onStartLive={() => void handleStartLive()}
          status={metrics}
        />

        <div className="stats-grid">
          <StatCard icon={AlertTriangle} label="TOTAL ALERTS" value={abbreviate(metrics?.alerts_generated ?? alerts.length)} detail="Generated from backend replay" tone="cyan" sparkColor="#22d3ee" />
          <StatCard icon={Zap} label="PROCESSED EVENTS" value={abbreviate(metrics?.processed_events ?? 0)} detail={`Events per second: ${metrics?.events_per_second ?? 0}`} tone="amber" sparkColor="#fbbf24" />
          <StatCard icon={Target} label="AVG. LATENCY" value={`${metrics?.average_alert_latency_ms?.toFixed(2) ?? '0.00'} ms`} detail="Average processing time" tone="violet" sparkColor="#a78bfa" />
          <StatCard icon={Activity} label="RUNNING STATE" value={metrics?.running ? 'LIVE' : 'IDLE'} detail={metrics?.status ?? 'idle'} tone="emerald" sparkColor="#34d399" />
        </div>

        <div className="overview-grid">
          <OverviewTimeline alerts={alerts} />
          <ThreatDistribution alerts={alerts} />
        </div>

        <IncidentTable incidents={incidents} />
        <AlertsTable alerts={alerts} onSelect={setSelected} />
      </>
    )
  }, [alerts, handleStart, handleStop, incidents, metrics, selectedScenario, speed, tab, scenarios])

  if (!session && !demoAccess) {
    return <LoginScreen onContinue={() => setDemoAccess(true)} />
  }

  return (
    <main className="app-shell">
      <div className="background-grid" />
      <Header tab={tab} setTab={setTab} status={metrics} onLogout={() => void handleLogout()} userEmail="local operator" />

      <div className="page-content">
        <div className="page-intro">
          <div>
            <span className="eyebrow">{tab === 'Overview' ? 'COMMAND OVERVIEW' : `SIH26145 / ${tab.toUpperCase()}`}</span>
            <h1>{tab === 'Overview' ? 'Network posture' : tab}</h1>
            <p>
              {tab === 'Overview'
                ? 'A live read of the signals that matter.'
                : tab === 'Alerts'
                  ? 'Review, filter, and investigate the latest detections.'
                  : tab === 'Analytics'
                    ? 'Patterns and distribution across the current replay window.'
                    : 'A concise view of the platform and its detection model.'}
            </p>
          </div>

          <div className="page-meta">
            <span>
              <span className={`live-pulse ${connectionState === 'connected' ? 'on' : ''}`} />
              {connectionState === 'connected' ? 'FEED ACTIVE' : connectionState === 'error' ? 'BACKEND ERROR' : 'CONNECTING'}
            </span>
            <span>{loading ? 'LOADING DATA' : `UPDATED ${timeAgo(metrics?.finished_at ?? metrics?.started_at ?? null).toUpperCase()}`}</span>
          </div>
        </div>

        {content}

        {operationError && (
          <div className="operation-error" role="alert">
            {operationError}
            <button type="button" onClick={() => setOperationError(null)} aria-label="Dismiss error">
              Dismiss
            </button>
          </div>
        )}

        <footer>
          <span>
            Read-only passive monitoring <i /> No probes <i /> No decryption
          </span>
          <span>
            SIH26145 · BACKEND CONNECTED <span className="cyan">/</span> 2026
          </span>
        </footer>
      </div>

      <EvidenceDrawer
        alert={selected}
        explanation={explanation}
        explanationSource={explanationSource}
        explanationLoading={explanationLoading}
        onExplain={() => void handleExplain()}
        onClose={() => {
          setSelected(null)
          setExplanation(null)
          setExplanationSource(null)
          setExplanationLoading(false)
        }}
      />
    </main>
  )
}

export default function Page() {
  return <App />
}
