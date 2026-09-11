import { useMemo } from 'react'
import { formatBytes, formatNumber, severityForClass, THREAT_COLORS } from '../lib/format'

function Card({ label, value, sub, color }) {
  return (
    <div className="stat-card">
      <div className="stat-num" style={{ color }}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  )
}

export default function StatCards({ stats }) {
  const perClass = stats?.per_threat_class || {}
  const severity = stats?.severity || {}
  const stream = stats?.stream || {}

  const totalAlerts = useMemo(
    () => Object.values(perClass).reduce((a, b) => a + b, 0),
    [perClass]
  )
  const topClass = useMemo(() => {
    const entries = Object.entries(perClass)
    if (!entries.length) return null
    entries.sort((a, b) => b[1] - a[1])
    return entries[0]
  }, [perClass])

  const severities = useMemo(() => {
    const map = { critical: 0, high: 0, medium: 0, info: 0 }
    for (const [cls, n] of Object.entries(perClass)) {
      const sev = severity[cls] || severityForClass(cls)
      map[sev] = (map[sev] || 0) + n
    }
    return map
  }, [perClass, severity])

  return (
    <section className="stats-row">
      <Card
        label="Flows observed"
        value={formatNumber(stats?.total_flows)}
        sub={`${formatBytes(stats?.total_bytes)} total`}
        color="#4fc1ff"
      />
      <Card
        label="Alerts raised"
        value={formatNumber(totalAlerts)}
        sub="across all history"
        color="#ff4d4f"
      />
      <Card
        label="Live throughput"
        value={formatNumber(stream?.throughput_fps)}
        sub="flows / second"
        color="#3fb950"
      />
      <Card
        label="Flows processed"
        value={formatNumber(stream?.processed)}
        sub="this session"
        color="#a371f7"
      />
      {topClass ? (
        <Card
          label="Top threat"
          value={topClass[0]}
          sub={`${formatNumber(topClass[1])} alerts`}
          color={THREAT_COLORS[topClass[0]] || '#e6edf3'}
        />
      ) : (
        <Card label="Top threat" value="—" sub="no alerts yet" color="#8b949e" />
      )}

      <div className="severity-strip">
        <span className="hl">Severity</span>
        {['critical', 'high', 'medium', 'info'].map((sev) => (
          <span className="sev-item" key={sev}>
            <span className="sev-dot" style={{ background: sevColor(sev) }} />
            {sev} <b>{formatNumber(severities[sev] || 0)}</b>
          </span>
        ))}
      </div>
    </section>
  )
}

function sevColor(sev) {
  return {
    critical: '#ff4d4f',
    high: '#e6b450',
    medium: '#4fc1ff',
    info: '#8b949e',
  }[sev]
}