import { useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../lib/api'

const MAX_ALERTS = 400
const MAX_FLOWS = 220
const MAX_SERIES = 120
const BUCKET_MS = 5000

export function useRealtime() {
  const [connState, setConnState] = useState('connecting')
  const [stats, setStats] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [flows, setFlows] = useState([])
  const [series, setSeries] = useState([])
  const [top, setTop] = useState({ sources: [], destinations: [] })
  const wsRef = useRef(null)
  const reconnectTimer = useRef(null)

  // ------------------------------------------------------------------
  // Initial REST snapshot + periodic refreshes of slower-moving data
  // ------------------------------------------------------------------
  useEffect(() => {
    let cancelled = false
    async function bootstrap() {
      try {
        const [st, al, fl, s] = await Promise.all([
          api.fetchStats(),
          api.fetchAlerts(MAX_ALERTS),
          api.fetchFlows(MAX_FLOWS),
          api.fetchSeries(5, MAX_SERIES),
        ])
        if (cancelled) return
        setStats(st)
        setAlerts((al.alerts || []).slice(0, MAX_ALERTS))
        setFlows((fl.flows || []).slice(0, MAX_FLOWS))
        setSeries((s.buckets || []).map((b) => ({
          ts: Date.parse(b.start),
          flows: b.flows,
          bytes: b.bytes,
          alerts: b.alerts,
          classes: b.classes || {},
        })))
      } catch (err) {
        console.warn('bootstrap failed', err)
      }
    }
    bootstrap()

    const topTimer = setInterval(async () => {
      try {
        const t = await api.fetchTop(8)
        if (!cancelled) setTop(t)
      } catch (_) {
        /* ignore */
      }
    }, 15_000)

    return () => {
      cancelled = true
      clearInterval(topTimer)
    }
  }, [])

  // ------------------------------------------------------------------
  // WebSocket live stream
  // ------------------------------------------------------------------
  useEffect(() => {
    let disposed = false

    function connect() {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const ws = new WebSocket(`${proto}//${window.location.host}/ws`)
      wsRef.current = ws

      ws.onopen = () => {
        if (!disposed) setConnState('open')
      }
      ws.onclose = () => {
        if (disposed) return
        setConnState('closed')
        reconnectTimer.current = setTimeout(connect, 2000)
      }
      ws.onerror = () => {
        ws.close()
      }

      ws.onmessage = (evt) => {
        let msg
        try {
          msg = JSON.parse(evt.data)
        } catch (_) {
          return
        }
        if (disposed) return

        if (msg.type === 'flow') {
          handleFlow(msg.data)
          if (msg.stats) setStats((prev) => ({ ...(prev || {}), stream: msg.stats }))
        } else if (msg.type === 'alert') {
          handleAlert(msg.data)
        }
      }
    }

    function handleFlow(data) {
      setFlows((prev) => [data, ...prev].slice(0, MAX_FLOWS))
      setSeries((prev) => {
        const tsMs = Math.floor((data.timestamp ?? Date.now() / 1000) * 1000)
        const key = Math.floor(tsMs / BUCKET_MS) * BUCKET_MS
        const cls = data.paired_alert
        const updated = [...prev]
        const last = updated[updated.length - 1]
        if (last && last.ts === key) {
          const next = { ...last, flows: last.flows + 1, bytes: last.bytes + (data.byte_count || 0) }
          if (cls) {
            next.alerts = (next.alerts || 0) + 1
            next.classes = { ...(next.classes || {}), [cls]: ((next.classes || {})[cls] || 0) + 1 }
          }
          updated[updated.length - 1] = next
          return updated
        }
        const bucket = {
          ts: key,
          flows: 1,
          bytes: data.byte_count || 0,
          alerts: cls ? 1 : 0,
          classes: cls ? { [cls]: 1 } : {},
        }
        return [...updated, bucket].slice(-MAX_SERIES)
      })
    }

    function handleAlert(data) {
      setAlerts((prev) => {
        if (prev.some((a) => a.flow_id === data.flow_id)) return prev
        return [data, ...prev].slice(0, MAX_ALERTS)
      })
      setStats((prev) =>
        prev ? { ...prev, total_alerts: (prev.total_alerts || 0) + 1 } : prev
      )
    }

    connect()
    return () => {
      disposed = true
      clearTimeout(reconnectTimer.current)
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  // ------------------------------------------------------------------
  // Controls
  // ------------------------------------------------------------------
  const doStart = useCallback(async () => {
    const s = await api.streamStart()
    setStats((prev) => (prev ? { ...prev, stream: s } : prev))
  }, [])

  const doStop = useCallback(async () => {
    const s = await api.streamStop()
    setStats((prev) => (prev ? { ...prev, stream: s } : prev))
  }, [])

  const doRate = useCallback(async (rateHz) => {
    const s = await api.streamRate(rateHz)
    setStats((prev) => (prev ? { ...prev, stream: s } : prev))
  }, [])

  const doReset = useCallback(async () => {
    const s = await api.resetData(true)
    const [al, fl, st, ser] = await Promise.all([
      api.fetchAlerts(MAX_ALERTS),
      api.fetchFlows(MAX_FLOWS),
      api.fetchStats(),
      api.fetchSeries(5, MAX_SERIES),
    ])
    setAlerts((al.alerts || []).slice(0, MAX_ALERTS))
    setFlows((fl.flows || []).slice(0, MAX_FLOWS))
    setStats(st)
    setSeries(
      (ser.buckets || []).map((b) => ({
        ts: Date.parse(b.start),
        flows: b.flows,
        bytes: b.bytes,
        alerts: b.alerts,
        classes: b.classes || {},
      }))
    )
  }, [])

  return {
    connState,
    stats,
    alerts,
    flows,
    series,
    top,
    controls: { doStart, doStop, doRate, doReset },
  }
}