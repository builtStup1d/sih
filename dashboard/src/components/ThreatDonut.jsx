import { useMemo, useState } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { colorForClass, formatNumber, THREAT_ORDER } from '../lib/format'

export default function ThreatDonut({ perThreatClass }) {
  const [active, setActive] = useState(null)
  const data = useMemo(() => {
    const entries = Object.entries(perThreatClass || {})
    entries.sort((a, b) => {
      const ia = THREAT_ORDER.indexOf(a[0])
      const ib = THREAT_ORDER.indexOf(b[0])
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || b[1] - a[1]
    })
    return entries.map(([name, value]) => ({ name, value, color: colorForClass(name) }))
  }, [perThreatClass])

  const total = useMemo(() => data.reduce((s, d) => s + d.value, 0), [data])

  return (
    <div className="donut-flex">
      <div className="donut-chart">
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={85}
              paddingAngle={2}
              stroke="#0d1117"
              onMouseEnter={(_, i) => setActive(i)}
              onMouseLeave={() => setActive(null)}
            >
              {data.map((d, i) => (
                <Cell key={d.name} fill={d.color} opacity={active == null || active === i ? 1 : 0.35} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#161b22',
                border: '1px solid #30363d',
                borderRadius: 8,
                fontSize: 12,
              }}
              formatter={(v) => [formatNumber(v), 'alerts']}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center">
          <div className="donut-total">{formatNumber(total)}</div>
          <div className="donut-caption">alerts</div>
        </div>
      </div>

      <div className="legend">
        {data.length === 0 && <div className="empty">No alerts yet.</div>}
        {data.map((d, i) => (
          <div
            className="legend-item"
            key={d.name}
            onMouseEnter={() => setActive(i)}
            onMouseLeave={() => setActive(null)}
          >
            <span className="swatch" style={{ background: d.color }} />
            <span>{d.name}</span>
            <span className="legend-val">{formatNumber(d.value)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}