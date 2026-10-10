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

// --- Bastion mock data ---

const bastionUsers = [
  {
    username: 'admin',
    role: 'admin',
    assets: [],
    comment: '初始管理员',
    created_at: new Date().toISOString(),
  },
  {
    username: 'ops',
    role: 'user',
    assets: ['asset-web-01'],
    comment: '运维工程师',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
]

const bastionAssets = [
  {
    id: 'asset-web-01',
    name: '生产-web-01',
    hostname: '192.168.1.10',
    port: 22,
    username: 'root',
    comment: '生产环境 Web 服务器',
    created_at: new Date().toISOString(),
  },
  {
    id: 'asset-db-01',
    name: '生产-db-01',
    hostname: '192.168.1.20',
    port: 22,
    username: 'admin',
    comment: '生产环境数据库',
    created_at: new Date(Date.now() - 86400000).toISOString(),
  },
]

const bastionSessions = [
  {
    id: 'sess-001',
    username: 'ops',
    asset_id: 'asset-web-01',
    asset_name: '生产-web-01',
    start_time: new Date(Date.now() - 3600000).toISOString(),
    end_time: new Date(Date.now() - 3500000).toISOString(),
    duration: '16m40s',
    status: 'closed',
    recording_path: '/recordings/2026-10-10/ops_sess-001.cast',
  },
  {
    id: 'sess-002',
    username: 'admin',
    asset_id: 'asset-db-01',
    asset_name: '生产-db-01',
    start_time: new Date(Date.now() - 600000).toISOString(),
    end_time: new Date(),
    duration: '10m',
    status: 'active',
    recording_path: '/recordings/2026-10-10/admin_sess-002.cast',
  },
]

const bastionAudit = [
  {
    timestamp: new Date().toISOString(),
    username: 'ops',
    session_id: 'sess-001',
    action: 'command',
    command: 'ls -la /var/log',
    blocked: false,
    client_ip: '10.0.0.5',
  },
  {
    timestamp: new Date(Date.now() - 100000).toISOString(),
    username: 'ops',
    session_id: 'sess-001',
    action: 'command',
    command: 'cat /etc/passwd',
    blocked: false,
    client_ip: '10.0.0.5',
  },
  {
    timestamp: new Date(Date.now() - 50000).toISOString(),
    username: 'admin',
    session_id: 'sess-002',
    action: 'blocked',
    command: 'rm -rf /',
    blocked: true,
    rule_id: 'ban-001',
    client_ip: '10.0.0.10',
  },
]

const bastionBanned = [
  { id: 'ban-001', pattern: 'rm -rf /', reason: 'destructive command', enabled: true },
  { id: 'ban-002', pattern: 'mkfs', reason: 'filesystem format', enabled: true },
  { id: 'ban-003', pattern: 'dd if=/dev/zero', reason: 'disk overwrite', enabled: true },
  { id: 'ban-004', pattern: ':(){:|:&};:', reason: 'fork bomb', enabled: true },
]

const send = (res, obj) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(obj))
}

const writeJSONErr = (res, status, msg) => {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ success: false, error: msg }))
}

createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')
  let total = 128

  // WAF routes
  switch (url.pathname) {
    case '/api/rules':
      if (req.method === 'GET') return send(res, { rules })
      return send(res, { success: true, count: 1 })
    case '/api/config':
      if (req.method === 'GET') return send(res, config)
      return send(res, { success: true })
    case '/api/allow':
      if (req.method === 'GET') return send(res, { ips: config.allow })
      if (req.method === 'POST') {
        let body = ''
        req.on('data', c => body += c)
        req.on('end', () => {
          try {
            const { ips } = JSON.parse(body)
            for (const ip of ips) {
              if (!config.allow.includes(ip)) config.allow.push(ip)
            }
            return send(res, { success: true, count: config.allow.length })
          } catch (e) {
            return writeJSONErr(res, 400, 'invalid json')
          }
        })
        return
      }
      if (req.method === 'DELETE') {
        let body = ''
        req.on('data', c => body += c)
        req.on('end', () => {
          try {
            const { ips } = JSON.parse(body)
            config.allow = config.allow.filter(ip => !ips.includes(ip))
            return send(res, { success: true })
          } catch (e) {
            return writeJSONErr(res, 400, 'invalid json')
          }
        })
        return
      }
      res.writeHead(405)
      return res.end('method not allowed')
    case '/api/deny':
      if (req.method === 'GET') return send(res, { ips: config.deny })
      if (req.method === 'POST') {
        let body = ''
        req.on('data', c => body += c)
        req.on('end', () => {
          try {
            const { ips } = JSON.parse(body)
            for (const ip of ips) {
              if (!config.deny.includes(ip)) config.deny.push(ip)
            }
            return send(res, { success: true, count: config.deny.length })
          } catch (e) {
            return writeJSONErr(res, 400, 'invalid json')
          }
        })
        return
      }
      if (req.method === 'DELETE') {
        let body = ''
        req.on('data', c => body += c)
        req.on('end', () => {
          try {
            const { ips } = JSON.parse(body)
            config.deny = config.deny.filter(ip => !ips.includes(ip))
            return send(res, { success: true })
          } catch (e) {
            return writeJSONErr(res, 400, 'invalid json')
          }
        })
        return
      }
      res.writeHead(405)
      return res.end('method not allowed')
    case '/api/metrics':
      total += Math.floor(Math.random() * 5)
      return send(res, {
        ...metrics,
        requests_total: total,
        rule_matched: metrics.rule_matched + Math.floor(Math.random() * 2),
        blocked: metrics.blocked + Math.floor(Math.random() * 2),
        rate_limited: metrics.rate_limited + Math.floor(Math.random() * 2),
      })
  }

  // Bastion routes
  if (url.pathname.startsWith('/api/bastion/')) {
    const path = url.pathname.slice('/api/bastion/'.length)

    if (path === 'users') {
      if (req.method === 'GET') return send(res, { users: bastionUsers, count: bastionUsers.length })
      if (req.method === 'POST') return send(res, { success: true })
      return send(res, { success: true, count: 1 })
    }

    if (path.startsWith('users/')) {
      if (req.method === 'GET') return send(res, { data: bastionUsers[0] })
      if (req.method === 'PUT') return send(res, { success: true })
      if (req.method === 'DELETE') return send(res, { success: true })
    }

    if (path === 'assets') {
      if (req.method === 'GET') return send(res, { assets: bastionAssets, count: bastionAssets.length })
      if (req.method === 'POST') return send(res, { success: true, id: 'asset-' + Date.now() })
    }

    if (path.startsWith('assets/')) {
      if (req.method === 'GET') return send(res, { data: bastionAssets[0] })
      if (req.method === 'PUT') return send(res, { success: true })
      if (req.method === 'DELETE') return send(res, { success: true })
    }

    if (path === 'sessions') {
      return send(res, {
        sessions: bastionSessions,
        count: bastionSessions.length,
        active: bastionSessions.filter(s => s.status === 'active').length,
      })
    }

    if (path === 'audit') {
      return send(res, { events: bastionAudit, count: bastionAudit.length })
    }

    if (path === 'banned') {
      if (req.method === 'GET') return send(res, { rules: bastionBanned, count: bastionBanned.length })
      if (req.method === 'POST') return send(res, { success: true, id: 'ban-' + Date.now() })
    }

    if (path === 'config') {
      if (req.method === 'GET') return send(res, {
        ssh_listen_addr: ':2222',
        api_listen_addr: ':8081',
        recording_dir: 'recordings',
        default_user: 'root',
        default_port: 22,
        max_sessions: 100,
        banner_msg: '=== GoWAF Bastion Host ===',
      })
      return send(res, { success: true })
    }

    if (path === 'healthz') {
      return send(res, { status: 'ok', ssh_listen: ':2222', active_sessions: 0 })
    }
  }

  // WAF health check
  if (url.pathname === '/api/healthz') {
    res.writeHead(200)
    return res.end('OK')
  }

  res.writeHead(404)
  return res.end('not found')
}).listen(8081, () => console.log('mock api on :8081'))
