package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sync"
)

// APIServer 提供 RESTful API 用于 WAF 配置和监控
type APIServer struct {
	waf      *WAF
	addr     string
	server   *http.Server
	upgradeMu sync.Mutex
}

// NewAPIServer 创建 API 服务器
func NewAPIServer(waf *WAF, addr string) *APIServer {
	return &APIServer{
		waf:   waf,
		addr:  addr,
	}
}

// Start 启动 API 服务器
func (s *APIServer) Start() error {
	mux := http.NewServeMux()

	// rules 相关接口
	mux.HandleFunc("/api/rules", s.handleRules())
	mux.HandleFunc("/api/rules/", s.handleRuleByID())

	// 配置相关接口
	mux.HandleFunc("/api/config", s.handleConfig())

	// IP 列表相关接口
	mux.HandleFunc("/api/allow", s.handleAllowList())
	mux.HandleFunc("/api/deny", s.handleDenyList())

	// 监控相关接口
	mux.HandleFunc("/api/metrics", s.handleMetrics())

	// 健康检查
	mux.HandleFunc("/healthz", s.handleHealth())

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	return s.server.ListenAndServe()
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
	ID       string `json:"id"`
	Category string `json:"category"`
	Where    string `json:"where"`
	Pattern  string `json:"pattern"`
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
	cfg := s.waf.config
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
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 解析 IP 列表
	allowList, err := parsePrefixesSlice(dto.Allow)
	if err != nil {
		http.Error(w, "invalid allow list: "+err.Error(), http.StatusBadRequest)
		return
	}
	denyList, err := parsePrefixesSlice(dto.Deny)
	if err != nil {
		http.Error(w, "invalid deny list: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 更新配置
	updated := s.waf.config
	updated.Mode = dto.Mode
	updated.MaxBody = dto.MaxBody
	updated.RPS = dto.RPS
	updated.Burst = dto.Burst
	updated.TrustXFF = dto.TrustXFF
	updated.BanStrikes = dto.BanStrikes
	updated.Allow = allowList
	updated.Deny = denyList

	// 注意：BanFor 需要解析 duration
	// 这里保持原值，实际可通过额外参数设置

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
	ips := ipListResponse{
		IPs: make([]string, len(s.waf.config.Allow)),
	}
	for i, p := range s.waf.config.Allow {
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
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	current := s.waf.config.Allow
	for _, ipStr := range ips.IPs {
		p, err := netip.ParsePrefix(ipStr)
		if err != nil {
			a, err2 := netip.ParseAddr(ipStr)
			if err2 != nil {
				http.Error(w, fmt.Sprintf("invalid ip %q: %v", ipStr, err), http.StatusBadRequest)
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
			current = append(current, p)
		}
	}

	s.waf.config.Allow = current
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *APIServer) removeFromAllowList(w http.ResponseWriter, r *http.Request) {
	var ips struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	current := s.waf.config.Allow
	var newAllow []netip.Prefix
	for _, p := range current {
		shouldRemove := false
		for _, ipStr := range ips.IPs {
			removeP, err := netip.ParsePrefix(ipStr)
			if err != nil {
				a, err2 := netip.ParseAddr(ipStr)
				if err2 == nil {
					removeP = netip.PrefixFrom(a, a.BitLen())
				}
			}
			if p.String() == removeP.String() {
				shouldRemove = true
				break
			}
		}
		if !shouldRemove {
			newAllow = append(newAllow, p)
		}
	}

	s.waf.config.Allow = newAllow
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
	ips := ipListResponse{
		IPs: make([]string, len(s.waf.config.Deny)),
	}
	for i, p := range s.waf.config.Deny {
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
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	current := s.waf.config.Deny
	for _, ipStr := range ips.IPs {
		p, err := netip.ParsePrefix(ipStr)
		if err != nil {
			a, err2 := netip.ParseAddr(ipStr)
			if err2 != nil {
				http.Error(w, fmt.Sprintf("invalid ip %q: %v", ipStr, err), http.StatusBadRequest)
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
			current = append(current, p)
		}
	}

	s.waf.config.Deny = current
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *APIServer) removeFromDenyList(w http.ResponseWriter, r *http.Request) {
	var ips struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ips); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	current := s.waf.config.Deny
	var newDeny []netip.Prefix
	for _, p := range current {
		shouldRemove := false
		for _, ipStr := range ips.IPs {
			removeP, err := netip.ParsePrefix(ipStr)
			if err != nil {
				a, err2 := netip.ParseAddr(ipStr)
				if err2 == nil {
					removeP = netip.PrefixFrom(a, a.BitLen())
				}
			}
			if p.String() == removeP.String() {
				shouldRemove = true
				break
			}
		}
		if !shouldRemove {
			newDeny = append(newDeny, p)
		}
	}

	s.waf.config.Deny = newDeny
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

// 监控相关处理器

func (s *APIServer) handleMetrics() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rules := *s.waf.rules.Load()
		json.NewEncoder(w).Encode(map[string]any{
			"requests_total":  s.waf.stats.total.Load(),
			"rule_matched":    s.waf.stats.matched.Load(),
			"blocked":         s.waf.stats.blocked.Load(),
			"rate_limited":    s.waf.stats.limited.Load(),
			"rules_loaded":    len(rules),
			"mode":            s.waf.config.Mode,
			"allow_count":     len(s.waf.config.Allow),
			"deny_count":      len(s.waf.config.Deny),
		})
	}
}

// 健康检查

func (s *APIServer) handleHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}