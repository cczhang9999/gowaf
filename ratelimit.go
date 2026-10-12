package main

import (
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const shardCount = 32

type bucket struct {
	tokens float64
	last   time.Time
}

type shard struct {
	mu sync.Mutex
	m  map[netip.Addr]*bucket
}

// Limiter 是按 IP 的令牌桶限流器。
// 核心思路:把不同 IP 散列到 32 个 shard(分片)中,每片一把锁。
// 这样同一时间只有落在同一分片的 IP 才会抢锁,不同分片完全并行 ——
// 高并发下不同 IP 基本不互相阻塞。
// 默认 32 分片,经验值:在 2 核机器上已能跑满网卡.
type Limiter struct {
	shards [shardCount]shard
	rate   float64 // 每秒补充的令牌数
	burst  float64
	now    func() time.Time // 可替换,便于测试注入假时钟
}

// PathLimiter 是按 IP + 路径的令牌桶限流器。
// 支持全局限流和路径特定限流。
type PathLimiter struct {
	// 全局限流器
	global *Limiter

	// 路径特定限流器 (key 是路径模式)
	pathLimiters map[string]*Limiter

	// 限流例外路径
	whitelist []string

	// 全局配置
	globalRate  float64
	globalBurst int
}

func NewLimiter(rps float64, burst int) *Limiter {
	l := &Limiter{rate: rps, burst: float64(burst), now: time.Now}
	for i := range l.shards {
		l.shards[i].m = make(map[netip.Addr]*bucket)
	}
	return l
}

// limiterKey:IPv6 用户通常拿到整段 /64,按单地址限流等于没限。
func limiterKey(ip netip.Addr) netip.Addr {
	if ip.Is6() && !ip.Is4In6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

func (l *Limiter) shardFor(ip netip.Addr) *shard {
	b := ip.As16()
	h := uint32(2166136261) // FNV-1a
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return &l.shards[h%shardCount]
}

// Allow 返回是否放行;被拒绝时同时返回建议的等待时间(用于 Retry-After)。
func (l *Limiter) Allow(ip netip.Addr) (bool, time.Duration) {
	ip = limiterKey(ip)
	now := l.now()
	s := l.shardFor(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.m[ip]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		s.m[ip] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// GC 清理长时间不活跃的桶,避免 map 被海量不同源 IP 撑爆内存。
func (l *Limiter) GC(ttl time.Duration) {
	now := l.now()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for ip, b := range s.m {
			if now.Sub(b.last) > ttl {
				delete(s.m, ip)
			}
		}
		s.mu.Unlock()
	}
}

// AutoBanner 实现 "攻击计数 → 自动封禁":
// 在时间窗口内违规达到阈值,自动封禁该 IP 一段时间。
type AutoBanner struct {
	mu      sync.Mutex
	strikes map[netip.Addr]*strike
	banned  map[netip.Addr]time.Time
	limit   int
	window  time.Duration
	dur     time.Duration
	now     func() time.Time
}

type strike struct {
	n     int
	first time.Time
}

func NewAutoBanner(limit int, window, dur time.Duration) *AutoBanner {
	return &AutoBanner{
		strikes: make(map[netip.Addr]*strike),
		banned:  make(map[netip.Addr]time.Time),
		limit:   limit, window: window, dur: dur,
		now: time.Now,
	}
}

func (b *AutoBanner) Banned(ip netip.Addr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	exp, ok := b.banned[ip]
	if !ok {
		return false
	}
	if b.now().After(exp) {
		delete(b.banned, ip)
		return false
	}
	return true
}

// Strike 记一次违规,返回本次是否触发了封禁。limit<=0 表示关闭自动封禁。
func (b *AutoBanner) Strike(ip netip.Addr) bool {
	if b.limit <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	s := b.strikes[ip]
	if s == nil || now.Sub(s.first) > b.window {
		s = &strike{first: now}
		b.strikes[ip] = s
	}
	s.n++
	if s.n >= b.limit {
		b.banned[ip] = now.Add(b.dur)
		delete(b.strikes, ip)
		return true
	}
	return false
}

func (b *AutoBanner) GC() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for ip, exp := range b.banned {
		if now.After(exp) {
			delete(b.banned, ip)
		}
	}
	for ip, s := range b.strikes {
		if now.Sub(s.first) > b.window {
			delete(b.strikes, ip)
		}
	}
}

// PathLimiterConfig 路径限流器配置
type PathLimiterConfig struct {
	GlobalRate  float64
	GlobalBurst int
	Whitelist   []string
	PathRules   []PathRateLimitRule
}

type PathRateLimitRule struct {
	Path  string
	Rate  float64
	Burst int
}

// NewPathLimiter 创建路径限流器
func NewPathLimiter(cfg PathLimiterConfig) *PathLimiter {
	pl := &PathLimiter{
		global:       NewLimiter(cfg.GlobalRate, cfg.GlobalBurst),
		pathLimiters: make(map[string]*Limiter),
		whitelist:    cfg.Whitelist,
		globalRate:   cfg.GlobalRate,
		globalBurst:  cfg.GlobalBurst,
	}

	// 创建路径特定限流器
	for _, rule := range cfg.PathRules {
		pl.pathLimiters[rule.Path] = NewLimiter(rule.Rate, rule.Burst)
	}

	return pl
}

// IsWhitelisted 检查路径是否在白名单中
func (pl *PathLimiter) IsWhitelisted(path string) bool {
	for _, p := range pl.whitelist {
		if p == path {
			return true
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

// Allow 检查是否允许请求,优先使用路径特定的限流规则
func (pl *PathLimiter) Allow(ip netip.Addr, path string) (bool, time.Duration) {
	// 检查白名单
	if pl.IsWhitelisted(path) {
		return true, 0
	}

	// 检查路径特定的限流规则
	for pathPattern, limiter := range pl.pathLimiters {
		if pathPattern == "*" || pathPattern == path {
			if ok, wait := limiter.Allow(ip); ok {
				return true, 0
			} else {
				return false, wait
			}
		}
		if strings.HasSuffix(pathPattern, "*") {
			prefix := strings.TrimSuffix(pathPattern, "*")
			if strings.HasPrefix(path, prefix) {
				if ok, wait := limiter.Allow(ip); ok {
					return true, 0
				} else {
					return false, wait
				}
			}
		}
	}

	// 使用全局限流规则
	return pl.global.Allow(ip)
}

// AllowWithGlobal 同时使用全局和路径限流规则,两个都通过才算通过
func (pl *PathLimiter) AllowWithGlobal(ip netip.Addr, path string) (bool, time.Duration) {
	// 检查白名单
	if pl.IsWhitelisted(path) {
		return true, 0
	}

	// 先检查路径限流
	for pathPattern, limiter := range pl.pathLimiters {
		if pathPattern == "*" || pathPattern == path {
			if ok, wait := limiter.Allow(ip); !ok {
				return false, wait
			}
		} else if strings.HasSuffix(pathPattern, "*") {
			prefix := strings.TrimSuffix(pathPattern, "*")
			if strings.HasPrefix(path, prefix) {
				if ok, wait := limiter.Allow(ip); !ok {
					return false, wait
				}
			}
		}
	}

	// 再检查全局限流
	return pl.global.Allow(ip)
}

// GC 清理所有限流器
func (pl *PathLimiter) GC(ttl time.Duration) {
	pl.global.GC(ttl)
	for _, limiter := range pl.pathLimiters {
		limiter.GC(ttl)
	}
}

// Stats 返回限流器统计信息
type LimiterStats struct {
	GlobalRate  float64     `json:"global_rate"`
	GlobalBurst int         `json:"global_burst"`
	Paths       []PathStats `json:"paths"`
}

type PathStats struct {
	Path  string  `json:"path"`
	Rate  float64 `json:"rate"`
	Burst int     `json:"burst"`
}

func (pl *PathLimiter) Stats() LimiterStats {
	stats := LimiterStats{
		GlobalRate:  pl.globalRate,
		GlobalBurst: pl.globalBurst,
		Paths:       make([]PathStats, 0, len(pl.pathLimiters)),
	}
	for path, limiter := range pl.pathLimiters {
		stats.Paths = append(stats.Paths, PathStats{
			Path:  path,
			Rate:  limiter.rate,
			Burst: int(limiter.burst),
		})
	}
	return stats
}
