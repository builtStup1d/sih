import { useMemo } from 'react'
import { formatBytes, formatClock, colorForClass, severityForClass, SEVERITY } from '../lib/format'

export default function TrafficStream({ flows }) {
  const rows = useMemo(() => flows.slice(0, 60), [flows])

  return (
    <div className="stream">
      <div className="stream-scroll">
        <table className="stream-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Flow</th>
              <th>Source</th>
              <th>→ Destination</th>
              <th>Proto</th>
              <th>Pkts</th>
              <th>Bytes</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="empty" style={{ textAlign: 'center' }}>
                  No traffic yet — start the live stream.
                </td>
              </tr>
            )}
            {rows.map((f) => (
              <tr
                key={f.flow_id}
                className={f.paired_alert ? 'row-alert' : undefined}
              >
                <td className="mono">{formatClock(f.timestamp)}</td>
                <td className="mono">{f.flow_id}</td>
                <td className="mono">{f.src_ip}:{f.src_port}</td>
                <td className="mono">{f.dst_ip}:{f.dst_port}</td>
                <td>{f.protocol}</td>
                <td className="mono num">{f.packet_count}</td>
                <td className="mono num">{formatBytes(f.byte_count)}</td>
                <td>
                  {f.paired_alert ? (
                    <span
                      className="pill"
                      style={{ background: colorForClass(f.paired_alert) }}
                    >
                      {f.paired_alert}
                    </span>
                  ) : (
                    <span
                      className="pill benign"
                      style={{ background: SEVERITY.info }}
                    >
                      benign
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}