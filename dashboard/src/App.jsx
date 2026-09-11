import { useRealtime } from './hooks/useRealtime'
import Header from './components/Header'
import StatCards from './components/StatCards'
import TimeSeriesChart from './components/TimeSeriesChart'
import AlertTimeline from './components/AlertTimeline'
import ThreatDonut from './components/ThreatDonut'
import TopIPs from './components/TopIPs'
import LiveFeed from './components/LiveFeed'
import TrafficStream from './components/TrafficStream'

export default function App() {
  const { connState, stats, alerts, flows, series, top, controls } = useRealtime()
  const stream = stats?.stream || {}

  return (
    <div className="app">
      <Header
        connState={connState}
        stream={stream}
        clients={stream?.clients}
        onStart={controls.doStart}
        onStop={controls.doStop}
        onRate={controls.doRate}
        onReset={controls.doReset}
      />

      <main className="main">
        <StatCards stats={stats} />

        <section className="panel span2">
          <div className="panel-head">
            <h2>Realtime traffic & alert rate</h2>
            <span className="hl">5s buckets · flows / throughput / alerts</span>
          </div>
          <TimeSeriesChart series={series} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Alerts by threat class</h2>
          </div>
          <ThreatDonut perThreatClass={stats?.per_threat_class} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Alert activity timeline</h2>
            <span className="hl">stacked by class</span>
          </div>
          <AlertTimeline series={series} />
        </section>

        <section className="panel span2">
          <div className="panel-head">
            <h2>Most active hosts</h2>
            <span className="hl">by alert count</span>
          </div>
          <TopIPs top={top} />
        </section>

        <section className="panel span2">
          <div className="panel-head">
            <h2>Live alert feed</h2>
            <span className="hl">color = severity</span>
          </div>
          <LiveFeed alerts={alerts} />
        </section>

        <section className="panel span2">
          <div className="panel-head">
            <h2>Realtime traffic stream</h2>
            <span className="hl">every flow observed on the wire</span>
          </div>
          <TrafficStream flows={flows} />
        </section>
      </main>

      <footer className="footer">
        FlowGuard AI · passive detection on metadata only · alerts & flows persisted to SQLite ·
        WebSocket realtime
      </footer>
    </div>
  )
}