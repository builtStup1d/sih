async function getJSON(path) {
  const res = await fetch(path)
  if (!res.ok) throw new Error(`${path} -> ${res.status}`)
  return res.json()
}

async function postJSON(path) {
  const res = await fetch(path, { method: 'POST' })
  if (!res.ok) throw new Error(`${path} -> ${res.status}`)
  return res.json()
}

export function fetchStats() {
  return getJSON('/api/stats')
}

export function fetchAlerts(limit = 300) {
  return getJSON(`/api/alerts?limit=${limit}`)
}

export function fetchFlows(limit = 100) {
  return getJSON(`/api/flows?limit=${limit}`)
}

export function fetchSeries(bucketSeconds = 5, points = 90) {
  return getJSON(`/api/series?bucket_seconds=${bucketSeconds}&points=${points}`)
}

export function fetchTop(n = 8) {
  return getJSON(`/api/top?n=${n}`)
}

export function streamStart() {
  return postJSON('/api/stream/start')
}

export function streamStop() {
  return postJSON('/api/stream/stop')
}

export function streamRate(rateHz) {
  return postJSON(`/api/stream/rate?rate_hz=${rateHz}`)
}

export function resetData(reseed = true) {
  return postJSON(`/api/reset?reseed=${reseed}`)
}