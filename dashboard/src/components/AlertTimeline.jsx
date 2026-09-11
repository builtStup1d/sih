import { useMemo } from 'react'
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts'
import { colorForClass, formatTime, THREAT_ORDER } from '../lib/format'

export default function AlertTimeline({ series }) {
  const { data, classes } = useMemo(() => {
    const clsSet = new Set()
    const rows = series.map((s) => {
      const row = { label: formatTime(new Date(s.ts).toISOString()) }
      for (const [cls, n] of Object.entries(s.classes || {})) {
        clsSet.add(cls)
        row[cls] = n
      }
      return row
    })
    const cls = [...clsSet].sort(
      (a, b) => THREAT_ORDER.indexOf(a) - THREAT_ORDER.indexOf(b)
    )
    return { data: rows, classes: cls }
  }, [series])

  if (!classes.length) {
    return <div className="empty">No alert activity in the window yet.</div>
  }

  return (
    <div className="chart-box">
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="#1f2733" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: '#8b949e', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: '#30363d' }}
            minTickGap={40}
          />
          <YAxis
            tick={{ fill: '#8b949e', fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={40}
          />
          <Tooltip
            cursor={{ fill: 'rgba(255,255,255,0.04)' }}
            contentStyle={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: 8,
              fontSize: 12,
            }}
            labelStyle={{ color: '#e6edf3' }}
          />
          <Legend wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
          {classes.map((cls) => (
            <Bar
              key={cls}
              dataKey={cls}
              stackId="a"
              fill={colorForClass(cls)}
              radius={cls === classes[classes.length - 1] ? [2, 2, 0, 0] : 0}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}