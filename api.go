package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"gowaf/bastion"
	"gowaf/internal/middleware"
)

// APIServer 提供 RESTful API 用于 WAF 配置和监控
// 当启用 SSH 堰垒机时,也提供堰垒机管理接口
type APIServer struct {
	waf        *WAF
	addr       string
	server     *http.Server
	upgradeMu  sync.Mutex
	log        *slog.Logger
	bastion    *bastion.SSHServer // SSH 堰垒机服务器(可选)
	bastionLog *slog.Logger
	apiToken   string   // API 认证 Token,空表示不启用认证
	upstream   string   // 上游服务器 URL,用于健康检查
	apiLimiter *Limiter // API 接口限流(按 IP),nil 表示不限流
}

// NewAPIServer creates API server
func NewAPIServer(waf *WAF, addr string, log *slog.Logger) *APIServer {
	return NewAPIServerWithBastion(waf, addr, "", "", nil, log)
}

// NewAPIServerWithBastion creates API server with SSH bastion and optional API token auth.
// apiToken: Bearer token for API auth (empty = no auth).
// upstream: upstream server URL for health checks (empty = skip).
func NewAPIServerWithBastion(waf *WAF, addr string, apiToken string, upstream string, bastionSrv *bastion.SSHServer, log *slog.Logger) *APIServer {
	if log == nil {
		log = slog.Default()
	}
	return &APIServer{
		waf:        waf,
		addr:       addr,
		log:        log,
		bastion:    bastionSrv,
		bastionLog: log,
		apiToken:   apiToken,
		upstream:   upstream,
	}
}

// SetAPIRateLimit enables per-IP rate limiting on the API server.
func (s *APIServer) SetAPIRateLimit(rps float64, burst int) {
	if rps > 0 {
		s.apiLimiter = NewLimiter(rps, burst)
	}
}

// apiRateLimit is a middleware that limits API requests per IP.
func (s *APIServer) apiRateLimit() func(http.Handler) http.Handler {
	if s.apiLimiter == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIPFromRequest(r)
			if ip != nil {
				ok, wait := s.apiLimiter.Allow(*ip)
				if !ok {
					w.Header().Set("Retry-After", fmt.Sprintf("%.0f", wait.Seconds()))
					writeJSONErr(w, http.StatusTooManyRequests, "rate limit exceeded")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Start 启动 API 服务器
func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	// WAF rules 相关接口
	mux.HandleFunc("/api/rules", s.handleRules())
	mux.HandleFunc("/api/rules/", s.handleRuleByID())

	// WAF 配置相关接口
	mux.HandleFunc("/api/config", s.handleConfig())

	// WAF IP 列表相关接口
	mux.HandleFunc("/api/allow", s.handleAllowList())
	mux.HandleFunc("/api/deny", s.handleDenyList())

	// WAF 监控相关接口
	mux.HandleFunc("/api/metrics", s.handleMetrics())

	// 健康检查
	mux.HandleFunc("/api/healthz", s.handleHealth())

	// SSH 堰垒机管理接口(始终注册,当未启用 SSH 时返回 503 而非 404)
	if s.bastion != nil {
		adminAPI := bastion.NewAdminAPI(s.bastion, s.bastionLog)
		bastionHandler := adminAPI.Handler()
		mux.Handle("/api/bastion/", http.StripPrefix("/api/bastion", bastionHandler))
		mux.Handle("/bastion/", http.StripPrefix("/bastion", bastionHandler))
	} else {
		bastionNotEnabled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSONErr(w, http.StatusServiceUnavailable, "bastion not enabled: start with -ssh flag")
		})
		mux.Handle("/api/bastion/", http.StripPrefix("/api/bastion", bastionNotEnabled))
		mux.Handle("/bastion/", http.StripPrefix("/bastion", bastionNotEnabled))
	}

	s.log.Info("api server starting", "addr", s.addr, "auth", len(s.apiToken) > 0)

	handler := middleware.Logging(s.log)(mux)
	handler = s.apiRateLimit()(handler)
	if s.apiToken != "" {
		handler = s.authToken(s.apiToken)(handler)
	}

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	return s.server.ListenAndServe()
}

// authToken 返回一个 HTTP 中间件,要求请求携带正确的 Bearer Token。
// 健康检查接口(/api/healthz)豁免认证,以便负载均衡器探测。
func (s *APIServer) authToken(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 健康检查豁免认证
			if r.URL.Path == "/api/healthz" {
				next.ServeHTTP(w, r)
				return
			}
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="gowaf-api"`)
				writeJSONErr(w, http.StatusUnauthorized, "missing Authorization header")
				return
			}
			parts := strings.SplitN(auth, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="gowaf-api"`)
				writeJSONErr(w, http.StatusUnauthorized, "invalid Authorization header format, expected 'Bearer <token>'")
				return
			}
			if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) != 1 {
				writeJSONErr(w, http.StatusForbidden, "invalid API token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Stop 停止 API 服务器
func (s *APIServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// 规则相关处理器

type rulesResponse struct {
	Rules []RuleDTO `json:"rules"`
}

type RuleDTO struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Where    string   `json:"where"`
	Pattern  string   `json:"pattern"`
	Keywords []string `json:"keywords,omitempty"`
}

// handleRules 处理 /api/rules 路由
func (s *APIServer) handleRules() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.getRules(w, r)
		case http.MethodPost:
			s.createRules(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *APIServer) getRules(w http.ResponseWriter, r *http.Request) {
	rules := *s.waf.rules.Load()
	dto := rulesResponse{
		Rules: make([]RuleDTO, len(rules)),
	}
	for i, r := range rules {
		dto.Rules[i] = RuleDTO{
			ID:       r.ID,
			Category: r.Category,
			Where:    r.Where,
			Pattern:  r.Pattern.String(),
			Keywords: r.keywords,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto)
}

func (s *APIServer) createRules(w http.ResponseWriter, r *http.Request) {
	var rawRules []ruleJSON
	if err := json.NewDecoder(r.Body).Decode(&rawRules); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	rules := make([]Rule, 0, len(rawRules))
	for _, r := range rawRules {
		re, err := compilePattern(r.Pattern)
		if err != nil {
			http.Error(w, fmt.Sprintf("rule %q: invalid pattern: %v", r.ID, err), http.StatusBadRequest)
			return
		}
		rules = append(rules, Rule{
			ID:       r.ID,
			Category: r.Category,
			Where:    r.Where,
			Pattern:  re,
			keywords: extractKeywords(r.Pattern),
		})
	}

	s.waf.SetRules(rules)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "count": len(rules)})
}

// handleRuleByID 处理 /api/rules/{id} 路由
func (s *APIServer) handleRuleByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/api/rules/"):]
		if id == "" {
			http.Error(w, "rule id required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.getRuleByID(w, r, id)
		case http.MethodPut:
			s.updateRuleByID(w, r, id)
		case http.MethodDelete:
			s.deleteRuleByID(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *APIServer) getRuleByID(w http.ResponseWriter, r *http.Request, id string) {
	rules := *s.waf.rules.Load()
	for _, rule := range rules {
		if rule.ID == id {
			dto := RuleDTO{
				ID:       rule.ID,
				Category: rule.Category,
				Where:    rule.Where,
				Pattern:  rule.Pattern.String(),
				Keywords: rule.keywords,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(dto)
			return
		}
	}
	http.Error(w, "rule not found", http.StatusNotFound)
}

func (s *APIServer) updateRuleByID(w http.ResponseWriter, r *http.Request, id string) {
	var rawRule struct {
		ID       string `json:"id"`
		Category string `json:"category"`
		Where    string `json:"where"`
		Pattern  string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rawRule); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	rules := *s.waf.rules.Load()
	newRules := make([]Rule, 0, len(rules))
	updated := false

	for _, rule := range rules {
		if rule.ID == id {
			re, err := compilePattern(rawRule.Pattern)
			if err != nil {
				http.Error(w, "invalid pattern: "+err.Error(), http.StatusBadRequest)
				return
			}
			newRules = append(newRules, Rule{
				ID:       rawRule.ID,
				Category: rawRule.Category,
				Where:    rawRule.Where,
				Pattern:  re,
				keywords: extractKeywords(rawRule.Pattern),
			})
			updated = true
		} else {
			newRules = append(newRules, rule)
		}
	}

	if !updated {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}

	s.waf.SetRules(newRules)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *APIServer) deleteRuleByID(w http.ResponseWriter, r *http.Request, id string) {
	rules := *s.waf.rules.Load()
	newRules := make([]Rule, 0, len(rules))
	deleted := false

	for _, rule := range rules {
		if rule.ID != id {
			newRules = append(newRules, rule)
		} else {
			deleted = true
		}
	}

	if !deleted {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}

	s.waf.SetRules(newRules)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func compilePattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

// 配置相关处理器

type configResponse struct {
	Mode       string   `json:"mode"`
	MaxBody    int64    `json:"maxBody"`
	RPS        float64  `json:"rps"`
	Burst      int      `json:"burst"`
	TrustXFF   bool     `json:"trustXFF"`
	BanStrikes int      `json:"banStrikes"`
	BanFor     string   `json:"banFor"`
	Allow      []string `json:"allow"`
	Deny       []string `json:"deny"`
}

func (s *APIServer) handleConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.getConfig(w, r)
		case http.MethodPut:
			s.updateConfig(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *APIServer) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.waf.getConfig()
	allowStrs := make([]string, len(cfg.Allow))
	for i, p := range cfg.Allow {
		allowStrs[i] = p.String()
	}
	denyStrs := make([]string, len(cfg.Deny))
	for i, p := range cfg.Deny {
		denyStrs[i] = p.String()
	}

	dto := configResponse{
		Mode:       cfg.Mode,
		MaxBody:    cfg.MaxBody,
		RPS:        cfg.RPS,
		Burst:      cfg.Burst,
		TrustXFF:   cfg.TrustXFF,
		BanStrikes: cfg.BanStrikes,
		BanFor:     cfg.BanFor.String(),
		Allow:      allowStrs,
		Deny:       denyStrs,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto)
}

func (s *APIServer) updateConfig(w http.ResponseWriter, r *http.Request) {
	var dto configResponse
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	// 验证 mode
	if dto.Mode != "" && dto.Mode != ModeBlock && dto.Mode != ModeDetect {
		writeJSONErr(w, http.StatusBadRequest, "mode must be 'block' or 'detect', got: "+dto.Mode)
		return
	}

	// 解析 IP 列表
	allowList, err := parsePrefixesSlice(dto.Allow)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid allow list: "+err.Error())
		return
	}
	denyList, err := parsePrefixesSlice(dto.Deny)
	if err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid deny list: "+err.Error())
		return
	}

	// 解析 BanFor duration
	banFor := s.waf.getConfig().BanFor
	if dto.BanFor != "" {
		d, err := time.ParseDuration(dto.BanFor)
		if err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid banFor duration: "+err.Error())
			return
		}
		banFor = d
	}

	// 原子替换整个配置
	updated := *s.waf.getConfig()
	updated.Mode = dto.Mode
	updated.MaxBody = dto.MaxBody
	updated.RPS = dto.RPS
	updated.Burst = dto.Burst
	updated.TrustXFF = dto.TrustXFF
	updated.BanStrikes = dto.BanStrikes
	updated.BanFor = banFor
	updated.Allow = allowList
	updated.Deny = denyList

	s.waf.SetConfig(updated)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func parsePrefixesSlice(strs []string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, s := range strs {
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return nil, fmt.Errorf("invalid ip/cidr %q: %w", s, err)
			}
			result = append(result, netip.PrefixFrom(a, a.BitLen()))
		} else {
			result = append(result, p)
		}
	}
	return result, nil
}

// IP 列表处理器

type ipListResponse struct {
	IPs []string `json:"ips"`
}

// writeJSONErr 输出统一的 JSON 错误,方便前端展示具体原因。
func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": msg})
}

func (s *APIServer) handleAllowList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.getAllowList(w, r)
		case http.MethodPost:
			s.addToAllowList(w, r)
		case http.MethodDelete:
			s.removeFromAllowList(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *APIServer) getAllowList(w http.ResponseWriter, r *http.Request) {
	cfg := s.waf.getConfig()
	ips := ipListResponse{
		IPs: make([]string, len(cfg.Allow)),
	}
	for i, p := range cfg.Allow {
		ips.IPs[i] = p.String()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

func (s *APIServer) addToAllowList(w http.ResponseWriter, r *http.Request) {
	var ips struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	if len(ips.IPs) == 0 {
		writeJSONErr(w, http.StatusBadRequest, "ips list is empty")
		return
	}

	current := s.waf.getConfig().Allow
	var toAdd []netip.Prefix
	for _, ipStr := range ips.IPs {
		p, err := netip.ParsePrefix(ipStr)
		if err != nil {
			a, err2 := netip.ParseAddr(ipStr)
			if err2 != nil {
				writeJSONErr(w, http.StatusBadRequest, "invalid ip/cidr \""+ipStr+"\"")
				return
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		// Check if already exists by string comparison
		exists := false
		for _, existing := range current {
			if existing.String() == p.String() {
				exists = true
				break
			}
		}
		if !exists {
			toAdd = append(toAdd, p)
		}
	}

	count := s.waf.AddAllow(toAdd)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "count": count})
}

func (s *APIServer) removeFromAllowList(w http.ResponseWriter, r *http.Request) {
	var ips struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	var toRemove []netip.Prefix
	for _, ipStr := range ips.IPs {
		p, err := netip.ParsePrefix(ipStr)
		if err != nil {
			a, err2 := netip.ParseAddr(ipStr)
			if err2 == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		toRemove = append(toRemove, p)
	}

	s.waf.RemoveAllow(toRemove)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// 黑名单处理器

func (s *APIServer) handleDenyList() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.getDenyList(w, r)
		case http.MethodPost:
			s.addToDenyList(w, r)
		case http.MethodDelete:
			s.removeFromDenyList(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func (s *APIServer) getDenyList(w http.ResponseWriter, r *http.Request) {
	cfg := s.waf.getConfig()
	ips := ipListResponse{
		IPs: make([]string, len(cfg.Deny)),
	}
	for i, p := range cfg.Deny {
		ips.IPs[i] = p.String()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

func (s *APIServer) addToDenyList(w http.ResponseWriter, r *http.Request) {
	var ips struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	if len(ips.IPs) == 0 {
		writeJSONErr(w, http.StatusBadRequest, "ips list is empty")
		return
	}

	current := s.waf.getConfig().Deny
	var toAdd []netip.Prefix
	for _, ipStr := range ips.IPs {
		p, err := netip.ParsePrefix(ipStr)
		if err != nil {
			a, err2 := netip.ParseAddr(ipStr)
			if err2 != nil {
				writeJSONErr(w, http.StatusBadRequest, "invalid ip/cidr \""+ipStr+"\"")
				return
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		// Check if already exists by string comparison
		exists := false
		for _, existing := range current {
			if existing.String() == p.String() {
				exists = true
				break
			}
		}
		if !exists {
			toAdd = append(toAdd, p)
		}
	}

	count := s.waf.AddDeny(toAdd)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true, "count": count})
}

func (s *APIServer) removeFromDenyList(w http.ResponseWriter, r *http.Request) {
	var ips struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	current := s.waf.getConfig().Deny
	var toRemove []netip.Prefix
	for _, p := range current {
		for _, ipStr := range ips.IPs {
			removeP, err := netip.ParsePrefix(ipStr)
			if err != nil {
				a, err2 := netip.ParseAddr(ipStr)
				if err2 == nil {
					removeP = netip.PrefixFrom(a, a.BitLen())
				}
			}
			if p.String() == removeP.String() {
				toRemove = append(toRemove, p)
				break
			}
		}
	}

	s.waf.RemoveDeny(toRemove)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// 监控相关处理器

func (s *APIServer) handleMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := s.waf.getConfig()
		w.Header().Set("Content-Type", "application/json")
		rules := *s.waf.rules.Load()
		json.NewEncoder(w).Encode(map[string]any{
			"requests_total": s.waf.stats.total.Load(),
			"rule_matched":   s.waf.stats.matched.Load(),
			"blocked":        s.waf.stats.blocked.Load(),
			"rate_limited":   s.waf.stats.limited.Load(),
			"rules_loaded":   len(rules),
			"mode":           cfg.Mode,
			"allow_count":    len(cfg.Allow),
			"deny_count":     len(cfg.Deny),
		})
	}
}

// 健康检查

// clientIPFromRequest extracts the client IP from RemoteAddr.
// API server is an internal interface, so we don't trust X-Forwarded-For.
func clientIPFromRequest(r *http.Request) *netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	return &ip
}

func (s *APIServer) handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"status": "ok",
		}
		// 如果配置了上游,则探活上游
		if s.upstream != "" {
			if err := checkUpstream(s.upstream); err != nil {
				resp["status"] = "degraded"
				resp["upstream"] = "unreachable"
				resp["upstream_error"] = err.Error()
				w.WriteHeader(http.StatusServiceUnavailable)
			} else {
				resp["upstream"] = "reachable"
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// checkUpstream does a quick HEAD/GET to verify the upstream is reachable.
func checkUpstream(upstream string) error {
	u, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream URL has no host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, upstream, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("upstream unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	return nil
}
