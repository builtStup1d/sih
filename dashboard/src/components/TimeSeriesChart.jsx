import { useMemo } from 'react'
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts'
import { formatBytes, formatTime } from '../lib/format'

export default function TimeSeriesChart({ series }) {
  const data = useMemo(
    () =>
      series.map((s) => ({
        ...s,
        label: formatTime(new Date(s.ts).toISOString()),
      })),
    [series]
  )

  return (
    <div className="chart-box">
      <ResponsiveContainer width="100%" height={260}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke="#1f2733" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fill: '#8b949e', fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: '#30363d' }}
            minTickGap={40}
          />
          <YAxis
            yAxisId="flows"
            tick={{ fill: '#8b949e', fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={44}
          />
          <YAxis
            yAxisId="bytes"
            orientation="right"
            tick={{ fill: '#8b949e', fontSize: 11 }}
            tickLine={false}
            axisLine={false}
            width={52}
            tickFormatter={(v) => formatBytes(v)}
          />
          <Tooltip
            contentStyle={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: 8,
              fontSize: 12,
            }}
            labelStyle={{ color: '#e6edf3' }}
            formatter={(value, name) =>
              name === 'bytes' ? formatBytes(value) : formatNumber(value)
            }
          />
          <Legend wrapperStyle={{ fontSize: 12, color: '#8b949e' }} />
          <Area
            yAxisId="flows"
            name="flows"
            dataKey="flows"
            stroke="#4fc1ff"
            fill="#4fc1ff"
            fillOpacity={0.18}
            strokeWidth={2}
          />
          <Area
            yAxisId="bytes"
            name="bytes"
            dataKey="bytes"
            stroke="#a371f7"
            fill="#a371f7"
            fillOpacity={0.12}
            strokeWidth={2}
          />
          <Bar yAxisId="flows" name="alerts" dataKey="alerts" fill="#ff4d4f" radius={[2, 2, 0, 0]} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}

function formatNumber(v) {
  if (v == null) return '0'
  return Number(v).toLocaleString()
}