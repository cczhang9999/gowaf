// 轻量 IP / CIDR 解析与校验工具。
// 供 IP 列表页在发送前用,避免无效条目打到后端产生 400。

function isIPv4(s: string): boolean {
  const parts = s.split('.')
  if (parts.length !== 4) return false
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false // 全数字
    const n = Number(p)
    if (n < 0 || n > 255 || (p.length > 1 && p.startsWith('0'))) return false // 前导 0 非法
  }
  return true
}

function isIPv6(s: string): boolean {
  if (!s.includes(':')) return false
  // 去掉可能的 scope zone,如 fe80::1%eth0
  const zone = s.indexOf('%')
  if (zone !== -1) s = s.slice(0, zone)
  if (s.includes('.')) {
    // 形如 ::ffff:192.168.1.1 —— 最后一段必须是合法 IPv4
    const idx = s.lastIndexOf(':')
    const tail = s.slice(idx + 1)
    if (!isIPv4(tail)) return false
    s = s.slice(0, idx) + ':0'
  }
  // 压缩标记 :: 至多出现一次
  if ((s.match(/::/g) || []).length > 1) return false
  // 用 '::' 拆成两部分,每部分的 group 校验
  const halves = s.split('::')
  for (const half of halves) {
    if (!half) continue
    const groups = half.split(':')
    for (const g of groups) {
      if (!g) continue
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false
    }
  }
  return true
}

function isValidIp(s: string): boolean {
  return isIPv4(s) || isIPv6(s)
}

function isValidIpOrCidr(s: string): boolean {
  if (s.indexOf('/') === -1) return isValidIp(s)
  const parts = s.split('/')
  if (parts.length !== 2) return false
  const ip = parts[0]
  const prefix = parts[1]
  if (!/^\d+$/.test(prefix)) return false
  const n = Number(prefix)
  const max = ip.includes(':') ? 128 : 32
  if (n < 0 || n > max) return false
  return isValidIp(ip)
}

// parseIpInput 把输入拆成 IP/CIDR 条目。
// 按行拆分,行内再按逗号/顿号/分号/空白分隔;忽略空行和 # 注释(含行尾注释)。
export function parseIpInput(input: string): { valid: string[]; invalid: string[] } {
  const valid: string[] = []
  const invalid: string[] = []
  const lines = input.split(/\r?\n/)
  for (const line of lines) {
    const clean = line.replace(/#.*$/, '').trim() // 去掉行内注释
    if (!clean) continue
    for (const raw of clean.split(/[,，;]+|\s+/)) {
      const token = raw.trim()
      if (!token) continue
      if (isValidIpOrCidr(token)) valid.push(token)
      else invalid.push(token)
    }
  }
  return { valid, invalid }
}
