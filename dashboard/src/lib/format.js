export const SEVERITY = {
  critical: '#ff4d4f',
  high: '#e6b450',
  medium: '#4fc1ff',
  info: '#8b949e',
}

export const THREAT_COLORS = {
  benign: '#3fb950',
  ddos: '#ff4d4f',
  botnet_beaconing: '#e6b450',
  dga_dns_tunneling: '#a371f7',
  encrypted_malware: '#f778ba',
  port_scan: '#4fc1ff',
  exfiltration: '#ff7b72',
  anomalous_unclassified: '#ffa657',
}

export const SEVERITY_FOR_CLASS = {
  benign: 'info',
  anomalous_unclassified: 'medium',
  port_scan: 'medium',
  botnet_beaconing: 'high',
  dga_dns_tunneling: 'high',
  encrypted_malware: 'high',
  ddos: 'critical',
  exfiltration: 'critical',
}

export const THREAT_ORDER = [
  'ddos',
  'exfiltration',
  'encrypted_malware',
  'botnet_beaconing',
  'dga_dns_tunneling',
  'port_scan',
  'anomalous_unclassified',
  'benign',
]

export function colorForClass(cls) {
  return THREAT_COLORS[cls] || '#8b949e'
}

export function severityForClass(cls) {
  return SEVERITY_FOR_CLASS[cls] || 'medium'
}

export function formatBytes(n) {
  if (n == null || isNaN(n)) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = Number(n)
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

export function formatNumber(n) {
  if (n == null || isNaN(n)) return '0'
  return Number(n).toLocaleString()
}

export function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d)) return '—'
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatClock(epochSeconds) {
  if (epochSeconds == null) return '—'
  const d = new Date(epochSeconds * 1000)
  if (isNaN(d)) return '—'
  return d.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function shortIp(ip) {
  return ip || '?'
}