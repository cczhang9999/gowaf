// Minimal mock of the gowaf Go API server, so we can exercise the frontend
// in a browser without needing to build/run the Go binary.
import { createServer } from 'http'

const rules = [
  { id: 'scan-001', category: 'scanner', where: 'path', pattern: '/\\.\\.(/|\\\\)', keywords: [] },
  { id: 'sqli-001', category: 'sqli', where: 'query', pattern: 'union[\\s/\\*\\-]+select', keywords: [] },
  { id: 'xss-001', category: 'xss', where: 'query', pattern: '<script[\\s\\S]*?>', keywords: [] },
]

const config = {
  mode: 'block',
  maxBody: 1048576,
  rps: 20,
  burst: 40,
  trustXFF: false,
  banStrikes: 5,
  banFor: '10m0s',
  allow: ['127.0.0.1'],
  deny: [],
}

const metrics = {
  requests_total: 128,
  rule_matched: 9,
  blocked: 4,
  rate_limited: 2,
  rules_loaded: rules.length,
  mode: 'block',
  allow_count: config.allow.length,
  deny_count: config.deny.length,
}

const send = (res, obj) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(obj))
}

createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')
  let total = 128
  switch (url.pathname) {
    case '/api/rules':
      if (req.method === 'GET') return send(res, { rules })
      return send(res, { success: true, count: 1 })
    case '/api/config':
      if (req.method === 'GET') return send(res, config)
      return send(res, { success: true })
    case '/api/allow':
      if (req.method === 'GET') return send(res, { ips: config.allow })
      return send(res, { success: true })
    case '/api/deny':
      if (req.method === 'GET') return send(res, { ips: config.deny })
      return send(res, { success: true })
    case '/api/metrics':
      // values drift so watchers/interval refreshes see changes
      total += Math.floor(Math.random() * 5)
      return send(res, {
        ...metrics,
        requests_total: total,
        rule_matched: metrics.rule_matched + Math.floor(Math.random() * 2),
        blocked: metrics.blocked + Math.floor(Math.random() * 2),
        rate_limited: metrics.rate_limited + Math.floor(Math.random() * 2),
      })
    case '/healthz':
      res.writeHead(200)
      return res.end('OK')
    default:
      res.writeHead(404)
      return res.end('not found')
  }
}).listen(8081, () => console.log('mock api on :8081'))
