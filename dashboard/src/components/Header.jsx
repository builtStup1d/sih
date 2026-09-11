import { useMemo } from 'react'

function StatusDot({ connState }) {
  const color =
    connState === 'open' ? '#3fb950' : connState === 'connecting' ? '#e6b450' : '#ff4d4f'
  const label =
    connState === 'open' ? 'LIVE' : connState === 'connecting' ? 'CONNECTING' : 'OFFLINE'
  return (
    <span className="status-pill" title={`WebSocket ${connState}`}>
      <span className="dot" style={{ background: color }} /> {label}
    </span>
  )
}

export default function Header({
  connState,
  stream,
  clients,
  onStart,
  onStop,
  onRate,
  onReset,
}) {
  const running = !!stream?.running

  const changeRate = (v) => {
    onRate(parseFloat(v))
  }
  const rateLabel = useMemo(() => Number(stream?.rate_hz || 3).toFixed(1), [stream])

  return (
    <header className="header">
      <div className="header-title">
        <div className="brand">
          <span className="brand-mark">FG</span>
          <div>
            <h1>FlowGuard AI</h1>
            <p className="sub">Passive AI threat detection · unidirectional IP traffic</p>
          </div>
        </div>
        <StatusDot connState={connState} />
      </div>

      <div className="header-controls">
        <div className="ctrl-group">
          <span className="hl">Stream</span>
          {running ? (
            <button className="btn danger" onClick={onStop} title="Stop live traffic">
              ■ Stop
            </button>
          ) : (
            <button className="btn accent" onClick={onStart} title="Start live traffic">
              ▶ Start
            </button>
          )}
          <button className="btn" onClick={onReset} title="Reset local databases">
            ↺ Reset
          </button>
        </div>

        <div className="ctrl-group">
          <span className="hl">Rate</span>
          <input
            type="range"
            min="0.5"
            max="20"
            step="0.5"
            value={stream?.rate_hz ?? 3.0}
            onChange={(e) => changeRate(e.target.value)}
          />
          <span className="hl mono">{rateLabel}/s</span>
        </div>

        <div className="ctrl-group">
          <span className="hl">
            Clients <b className="clients-badge">{clients}</b>
          </span>
        </div>
      </div>
    </header>
  )
}