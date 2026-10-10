package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	// apiAddr 指定 API 服务器监听地址,默认为 :8081
	apiAddr = flag.String("api-addr", ":8081", "API 服务器监听地址,0 表示禁用")
)

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid ip/cidr %q", part)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// buildProxy 构造反向代理,负责把 WAF 放行的请求转发到源站。
func buildProxy(target *url.URL, log *slog.Logger) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded() // 覆盖客户端自带的 XFF,防止伪造
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
		ErrorHandler: func(rw http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream error", "err", err, "path", trunc(r.URL.Path, 200))
			http.Error(rw, "bad gateway", http.StatusBadGateway)
		},
	}
}

// buildServer 构造 HTTP 服务器,带防慢速攻击的超时设置。
func buildServer(listen string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second, // 抵御 slowloris
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
}

func main() {
	var (
		listen    = flag.String("listen", ":8080", "WAF 监听地址")
		upstream  = flag.String("upstream", "http://127.0.0.1:9000", "被保护的源站地址")
		mode      = flag.String("mode", ModeBlock, "block | detect")
		rps       = flag.Float64("rps", 20, "每 IP 每秒请求数,0 关闭限流")
		burst     = flag.Int("burst", 40, "令牌桶突发容量")
		rulesPath = flag.String("rules", "", "自定义规则 JSON(留空用内置规则),SIGHUP 热加载")
		maxBody   = flag.Int64("max-body", 1<<20, "最大检查的请求体字节数")
		trustXFF  = flag.Bool("trust-xff", false, "信任 X-Forwarded-For(仅当前面有可信代理)")
		allow     = flag.String("allow", "", "白名单 IP/CIDR,逗号分隔")
		deny      = flag.String("deny", "", "黑名单 IP/CIDR,逗号分隔")
		banStrike = flag.Int("ban-strikes", 5, "1 分钟内违规多少次自动封禁,0 关闭")
		banFor    = flag.Duration("ban-for", 10*time.Minute, "自动封禁时长")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	fatal := func(msg string, err error) {
		log.Error(msg, "err", err)
		os.Exit(1)
	}

	target, err := url.Parse(*upstream)
	if err != nil || target.Host == "" {
		fatal("invalid -upstream", fmt.Errorf("%q", *upstream))
	}
	allowList, err := parsePrefixes(*allow)
	if err != nil {
		fatal("invalid -allow", err)
	}
	denyList, err := parsePrefixes(*deny)
	if err != nil {
		fatal("invalid -deny", err)
	}

	rules := DefaultRules()
	if *rulesPath != "" {
		if rules, err = LoadRules(*rulesPath); err != nil {
			fatal("load rules", err)
		}
	}

	w := New(Config{
		Mode: *mode, MaxBody: *maxBody, RPS: *rps, Burst: *burst,
		Allow: allowList, Deny: denyList, TrustXFF: *trustXFF,
		BanStrikes: *banStrike, BanFor: *banFor,
	}, rules, log)

	proxy := buildProxy(target, log)
	srv := buildServer(*listen, w.Handler(proxy))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go w.Run(ctx)

	// SIGHUP 热加载规则:编译失败则保留旧规则,不影响线上流量
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if *rulesPath == "" {
					log.Info("SIGHUP ignored: using built-in rules")
					continue
				}
				rs, err := LoadRules(*rulesPath)
				if err != nil {
					log.Error("reload failed, keeping old rules", "err", err)
					continue
				}
				w.SetRules(rs)
				log.Info("rules reloaded", "count", len(rs))
			}
		}
	}()

	// 优雅退出:停止接收新连接,等在途请求处理完
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	// 启动 API 服务器
	var apiServer *APIServer
	if *apiAddr != "0" {
		apiServer = NewAPIServer(w, *apiAddr)
		go func() {
			if err := apiServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("api server error", "err", err)
			}
		}()
	}

	log.Info("waf started", "listen", *listen, "upstream", target.String(), "mode", *mode, "rules", len(rules))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("server", err)
	}

	// 停止 API 服务器
	if apiServer != nil {
		_ = apiServer.Stop()
	}
	log.Info("waf stopped")
}
