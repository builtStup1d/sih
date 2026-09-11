import { useMemo, useRef, useState, useEffect } from 'react'
import { formatTime, colorForClass, severityForClass, SEVERITY } from '../lib/format'

const SEVERITY_OPTIONS = ['', 'critical', 'high', 'medium', 'info']

export default function LiveFeed({ alerts }) {
  const [classFilter, setClassFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [search, setSearch] = useState('')
  const [autoScroll, setAutoScroll] = useState(true)
  const [follow, setFollow] = useState(false)
  const scrollRef = useRef(null)

  const allClasses = useMemo(
    () => [...new Set(alerts.map((a) => a.threat_class))].sort(),
    [alerts]
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return alerts.filter((a) => {
      if (classFilter && a.threat_class !== classFilter) return false
      if (severityFilter && (severityForClass(a.threat_class) !== severityFilter)) return false
      if (q) {
        const haystack = [a.flow_id, a.src_ip, a.dst_ip, a.threat_class, a.model_source]
          .concat(a.evidence || [])
          .join(' ')
          .toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [alerts, classFilter, severityFilter, search])

  useEffect(() => {
    if (autoScroll && filtered.length) {
      scrollRef.current?.scrollTo({ top: 0 })
    }
  }, [filtered.length, autoScroll])

  return (
    <div className="feed">
      <div className="feed-toolbar">
        <input
          className="search"
          type="search"
          placeholder="Search flow id / ip / class / evidence…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select value={classFilter} onChange={(e) => setClassFilter(e.target.value)}>
          <option value="">all classes</option>
          {allClasses.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
        >
          <option value="">all severities</option>
          {SEVERITY_OPTIONS.slice(1).map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <label className="check">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
          />
          autoscroll
        </label>
        <span className="hl feed-count">
          {filtered.length} of {alerts.length}
        </span>
      </div>

      <div className="feed-scroll" ref={scrollRef}>
        <table className="feed-table">
          <thead>
            <tr>
              <th></th>
              <th>Time</th>
              <th>Flow ID</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Class</th>
              <th>Conf</th>
              <th>Model</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={9} className="empty" style={{ textAlign: 'center' }}>
                  No alerts match the current filters.
                </td>
              </tr>
            )}
            {filtered.map((a) => (
              <tr key={a.flow_id} className={`sev-${severityForClass(a.threat_class)}`}>
                <td>
                  <span
                    className="sev-dot"
                    style={{ background: SEVERITY[severityForClass(a.threat_class)] }}
                  />
                </td>
                <td className="mono">{formatTime(a.timestamp)}</td>
                <td className="mono">{a.flow_id}</td>
                <td className="mono">
                  {a.src_ip}:{a.src_port}
                </td>
                <td className="mono">
                  {a.dst_ip}:{a.dst_port}
                </td>
                <td>
                  <span
                    className="pill"
                    style={{ background: colorForClass(a.threat_class) }}
                  >
                    {a.threat_class}
                  </span>
                </td>
                <td className="mono">{Number(a.confidence).toFixed(2)}</td>
                <td className="hl">{a.model_source}</td>
                <td className="evidence" title={(a.evidence || []).join('; ')}>
                  {(a.evidence || []).join('; ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}