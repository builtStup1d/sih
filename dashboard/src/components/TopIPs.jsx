import { useMemo } from 'react'
import { formatNumber, THREAT_COLORS } from '../lib/format'

function BarList({ title, rows }) {
  const max = useMemo(() => Math.max(...rows.map(([, n]) => n), 1), [rows])
  return (
    <div className="bar-list">
      <h3 className="panel-sub">{title}</h3>
      {rows.length === 0 && <div className="empty">No data.</div>}
      {rows.map(([ip, n]) => {
        const pct = Math.max((n / max) * 100, 4)
        return (
          <div className="hbar-row" key={ip}>
            <span className="hbar-lbl" title={ip}>
              {ip}
            </span>
            <div className="hbar-track">
              <div
                className="hbar-fill"
                style={{ width: `${pct}%`, color: THREAT_COLORS.port_scan }}
              >
                {formatNumber(n)}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default function TopIPs({ top }) {
  return (
    <div className="top-ips">
      <BarList title="Top sources by alerts" rows={top?.sources || []} />
      <BarList title="Top destinations by alerts" rows={top?.destinations || []} />
    </div>
  )
}