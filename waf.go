package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ModeBlock  = "block"  // 命中即拦截
	ModeDetect = "detect" // 只记日志不拦截,用于新规则灰度观察
)

type Config struct {
	Mode       string
	MaxBody    int64   // 最多检查/缓存的请求体字节数,超出返回 413
	RPS        float64 // 每 IP 每秒请求数,<=0 关闭限流
	Burst      int
	Allow      []netip.Prefix // 白名单:直接放行
	Deny       []netip.Prefix // 黑名单:直接拒绝
	TrustXFF   bool           // 仅当本 WAF 前面确有一层可信代理时才开启
	BanStrikes int            // 窗口内违规多少次自动封禁,0 关闭
	BanWindow  time.Duration
	BanFor     time.Duration
}

// fieldPool 池化 Field 切片,避免每请求分配,降低 GC 压力。
var fieldPool = sync.Pool{
	New: func() any { return make([]Field, 0, 16) },
}

type WAF struct {
	config  Config
	rules   atomic.Pointer[[]Rule]        // 规则热更新:整体替换指针,读路径无锁
	kwRe    atomic.Pointer[regexp.Regexp] // 由所有规则关键词组合的全局预过滤正则
	limiter *Limiter
	banner  *AutoBanner
	log     *slog.Logger
	stats   struct{ total, matched, blocked, limited atomic.Int64 }
}

func New(cfg Config, rules []Rule, log *slog.Logger) *WAF {
	if cfg.Mode == "" {
		cfg.Mode = ModeBlock
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 1 << 20
	}
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.RPS) * 2
	}
	if cfg.BanWindow <= 0 {
		cfg.BanWindow = time.Minute
	}
	if cfg.BanFor <= 0 {
		cfg.BanFor = 10 * time.Minute
	}
	w := &WAF{config: cfg, log: log, banner: NewAutoBanner(cfg.BanStrikes, cfg.BanWindow, cfg.BanFor)}
	if cfg.RPS > 0 {
		w.limiter = NewLimiter(cfg.RPS, cfg.Burst)
	}
	w.SetRules(rules)
	return w
}

// SetRules 原子替换规则集,可在运行中安全调用(例如收到 SIGHUP)。
// 会从所有规则中提取关键词并编译一个全局预过滤正则。
// 若新规则集的关键词为空(所有模式都无法提取字面量),预过滤正则将为 nil,
// 此时 inspect 回退到原始行为(对每个字段跑完整的规则).
func (w *WAF) SetRules(rs []Rule) {
	w.rules.Store(&rs)

	var kws []string
	for _, r := range rs {
		kws = append(kws, r.keywords...)
	}
	if len(kws) > 0 {
		// 去重
		seen := make(map[string]struct{}, len(kws))
		var unique []string
		for _, k := range kws {
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				unique = append(unique, regexp.QuoteMeta(k))
			}
		}
		w.kwRe.Store(regexp.MustCompile(`(?i)` + strings.Join(unique, `|`)))
	} else {
		w.kwRe.Store(nil)
	}
}

// Run 启动后台清理协程,ctx 取消时退出。
func (w *WAF) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.limiter != nil {
				w.limiter.GC(10 * time.Minute)
			}
			w.banner.GC()
		}
	}
}

// Field 是一段待检测的请求内容及其来源位置。
type Field struct{ Where, Value string }

type Match struct{ RuleID, Category, Where string }

// rejectInfo 封装拒绝请求所需的所有信息,避免 reject 参数太多。
type rejectInfo struct {
	ID     string
	IP     netip.Addr
	Status int
	Reason string
	Match  *Match
}

var errBodyTooLarge = errors.New("body too large")

// extract 抽取 path / query / header / body。body 读出后会重新塞回 r.Body,上游照常能读到。
// 使用 sync.Pool 池化 Field 切片,减少每请求一次的分配,降低 GC 压力。
func (w *WAF) extract(r *http.Request) ([]Field, error) {
	fs := fieldPool.Get().([]Field)[:0]
	fs = append(fs, Field{"path", r.URL.Path})
	if r.URL.RawQuery != "" {
		fs = append(fs, Field{"query", r.URL.RawQuery})
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" { // 凭证不检测,也不进日志
			continue
		}
		for _, v := range vs {
			fs = append(fs, Field{"header:" + lk, v})
		}
	}
	if r.Body == nil || r.Body == http.NoBody {
		return fs, nil
	}
	if r.ContentLength > w.config.MaxBody {
		fieldPool.Put(fs)
		return nil, errBodyTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, w.config.MaxBody+1))
	if err != nil {
		fieldPool.Put(fs)
		return nil, err
	}
	if int64(len(b)) > w.config.MaxBody {
		fieldPool.Put(fs)
		return nil, errBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.TransferEncoding = nil

	// JSON 里的 ' 之类转义,必须先解码再检测,否则一个 \u 就能绕过
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasSuffix(ct, "json") {
		var v any
		if json.Unmarshal(b, &v) == nil {
			var ss []string
			collectJSON(v, &ss)
			for _, s := range ss {
				fs = append(fs, Field{"body", s})
			}
		}
	}
	fs = append(fs, Field{"body", string(b)})
	return fs, nil
}

func collectJSON(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case []any:
		for _, x := range t {
			collectJSON(x, out)
		}
	case map[string]any:
		for k, x := range t {
			*out = append(*out, k)
			collectJSON(x, out)
		}
	}
}

// inspect 对每个字段只 normalize 一次,再依次套用规则。
// 优化:先通过全局关键词预过滤,若字段中不含任何规则的关键词,
// 则跳过该字段的所有正则匹配(干净流量命中率极高)。
// 然后对每个规则再做一次关键词检查,跳过肯定无法匹配的规则。
func (w *WAF) inspect(fs []Field) *Match {
	rules := *w.rules.Load()
	kwRe := w.kwRe.Load()
	for _, f := range fs {
		if f.Value == "" {
			continue
		}
		// 快速预过滤:在原始值(大小写不敏感)及其最多 maxDecodeDepth 次 URL 解码后,
		// 检查是否包含全局关键词。全程不含任何关键词 → 跳过该字段的所有规则。
		if kwRe != nil && !keywordPresent(f.Value, kwRe) {
			continue
		}
		n := normalize(f.Value)
		for i := range rules {
			ru := &rules[i]
			if ru.Where != "" && !strings.HasPrefix(f.Where, ru.Where) {
				continue
			}
			// 单规则预过滤:该规则的关键词都不匹配 → 跳过
			if len(ru.keywords) > 0 && !containsAny(n, ru.keywords) {
				continue
			}
			if ru.Pattern.MatchString(n) {
				return &Match{RuleID: ru.ID, Category: ru.Category, Where: f.Where}
			}
		}
	}
	return nil
}

// keywordPresent 在原始字符串及其最多 maxDecodeDepth 次 URL 解码后,
// 检查是否包含全局关键词。用于快速跳过肯定无法匹配的字段。
// 使用 (?i) 不区分大小写,以处理原始值中的大小写变异。
func keywordPresent(s string, kwRe *regexp.Regexp) bool {
	for i := 0; i <= maxDecodeDepth; i++ {
		if kwRe.MatchString(s) {
			return true
		}
		d := unescape(s)
		if d == s {
			break
		}
		s = d
	}
	return false
}

func (w *WAF) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, _ := netip.ParseAddr(host)
	if w.config.TrustXFF {
		// 取最右一项:那是可信代理自己追加的,左边的内容客户端可以随意伪造
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.Unmap()
			}
		}
	}
	return ip.Unmap()
}

func inPrefixes(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (w *WAF) reject(rw http.ResponseWriter, r *http.Request, ri rejectInfo) {
	attrs := []any{"id", ri.ID, "ip", ri.IP.String(), "status", ri.Status, "reason", ri.Reason,
		"method", r.Method, "path", trunc(r.URL.Path, 200)}
	if ri.Match != nil {
		attrs = append(attrs, "rule", ri.Match.RuleID, "category", ri.Match.Category, "where", ri.Match.Where)
	}
	w.log.Warn("request rejected", attrs...)
	http.Error(rw, "request blocked by WAF, id="+ri.ID, ri.Status)
}

// Handler 把 WAF 作为中间件套在任意 http.Handler(这里是反向代理)前面。
func (w *WAF) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.stats.total.Add(1)
		ip := w.clientIP(r)

		if r.URL.Path == "/__waf/metrics" {
			w.serveMetrics(rw, r, ip)
			return
		}

		id := newID()
		rw.Header().Set("X-WAF-Request-ID", id)

		if inPrefixes(w.config.Allow, ip) {
			next.ServeHTTP(rw, r)
			return
		}
		if inPrefixes(w.config.Deny, ip) || w.banner.Banned(ip) {
			w.stats.blocked.Add(1)
			w.reject(rw, r, rejectInfo{ID: id, IP: ip, Status: http.StatusForbidden, Reason: "ip_denied"})
			return
		}
		if w.limiter != nil {
			if ok, wait := w.limiter.Allow(ip); !ok {
				w.stats.limited.Add(1)
				rw.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
				w.reject(rw, r, rejectInfo{ID: id, IP: ip, Status: http.StatusTooManyRequests, Reason: "rate_limited"})
				return
			}
		}

		fields, err := w.extract(r)
		if err != nil {
			status, reason := http.StatusBadRequest, "bad_body"
			if errors.Is(err, errBodyTooLarge) {
				status, reason = http.StatusRequestEntityTooLarge, "body_too_large"
			}
			w.stats.blocked.Add(1)
			w.reject(rw, r, rejectInfo{ID: id, IP: ip, Status: status, Reason: reason})
			return
		}

		m := w.inspect(fields)

		// 将 Field 切片归还池中,清除引用以避免 body 数据残留
		for i := range fields {
			fields[i] = Field{}
		}
		fieldPool.Put(fields)

		if m != nil {
			w.stats.matched.Add(1)
			if w.config.Mode == ModeBlock {
				w.stats.blocked.Add(1)
				if w.banner.Strike(ip) {
					w.log.Warn("ip banned", "ip", ip.String(), "for", w.config.BanFor.String())
				}
				w.reject(rw, r, rejectInfo{ID: id, IP: ip, Status: http.StatusForbidden, Reason: "rule_match", Match: m})
				return
			}
			w.log.Warn("rule matched (detect mode, not blocked)", "id", id, "ip", ip.String(),
				"rule", m.RuleID, "category", m.Category, "where", m.Where)
		}
		next.ServeHTTP(rw, r)
	})
}

// serveMetrics 只允许本机访问,避免把内部统计暴露给公网。
func (w *WAF) serveMetrics(rw http.ResponseWriter, r *http.Request, ip netip.Addr) {
	if !ip.IsLoopback() {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"requests_total": w.stats.total.Load(),
		"rule_matched":   w.stats.matched.Load(),
		"blocked":        w.stats.blocked.Load(),
		"rate_limited":   w.stats.limited.Load(),
		"rules_loaded":   len(*w.rules.Load()),
		"mode":           w.config.Mode,
	})
}
