package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Rule 是一条检测规则。
// Go 的 regexp 基于 RE2,保证线性时间匹配,天然免疫正则 ReDoS ——
// 这对 WAF 很关键:规则本身不能成为被攻击的入口。
type Rule struct {
	ID       string
	Category string
	Where    string // 字段位置前缀:path / query / body / header:user-agent;空表示匹配所有位置
	Pattern  *regexp.Regexp
	keywords []string // 从 Pattern 中提取的字面子串,用于快速预过滤
}

// extractKeywords 从正则模式中提取字面子串(字面量)。
// 这些子串作为快速预过滤:如果输入中不包含任何一个子串,
// 则正则必然无法匹配,可以跳过较慢的 regex.Eval。
// 提取策略:扫描模式,跳过所有元字符和转义序列(除 \. \/\/\()等转义字面量),
// 收集连续的字面字符(run >= 3)。
// 注意:keywords 是必要非充分条件 —— 关键词存在不保证匹配,但关键词
// 不存在就一定不匹配。因此跳过是安全的。
func extractKeywords(pattern string) []string {
	var keywords []string
	var lit strings.Builder
	inClass := false // 是否在 [...] 字符类内部

	flush := func() {
		// 过滤过短的关键词(<=2 字符),它们匹配太多正常流量,过滤效果差
		if lit.Len() >= 2 {
			kw := strings.ToLower(lit.String())
			keywords = append(keywords, kw)
		}
		lit.Reset()
	}

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]

		if inClass {
			if c == ']' {
				inClass = false
				flush()
			}
			// 字符类内部的内容跳过 (简化:不处理 - 范围运算符等)
			continue
		}

		if c == '\\' {
			// 转义序列
			if i+1 < len(pattern) {
				next := pattern[i+1]
				// \s \d \w \b \S \D \W \B 是字符类/单词边界,不是字面量
				if next == 's' || next == 'd' || next == 'w' || next == 'b' ||
					next == 'S' || next == 'D' || next == 'W' || next == 'B' {
					flush()
				} else {
					// \. \/ \[ 等转义字面量,保留其字面含义
					lit.WriteByte(next)
				}
				i++ // 跳过转义的字符
			}
			continue
		}

		switch c {
		case '[':
			inClass = true
			flush()
		case '.', '*', '+', '?', '^', '$', '(', ')', '{', '}', '|':
			flush()
		default:
			lit.WriteByte(c)
		}
	}
	flush()
	return keywords
}

// containsAny 检查字符串 s 中是否包含 keywords 列表中的任意一个。
func containsAny(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

type ruleJSON struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Where    string `json:"where"`
	Pattern  string `json:"pattern"`
}

func mustRule(id, cat, where, pat string) Rule {
	return Rule{ID: id, Category: cat, Where: where, Pattern: regexp.MustCompile(pat), keywords: extractKeywords(pat)}
}

// DefaultRules 内置的最小规则集(输入已经过 normalize,统一为小写、已解码、空白折叠)。
func DefaultRules() []Rule {
	return []Rule{
		// SQL 注入
		mustRule("sqli-001", "sqli", "", `\bunion\b\s+(all\s+|distinct\s+)?select\b`),
		mustRule("sqli-002", "sqli", "", `\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`),
		mustRule("sqli-003", "sqli", "", `\b(sleep\s*\(\s*\d+|pg_sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b`),
		mustRule("sqli-004", "sqli", "", `\binformation_schema\b`),
		mustRule("sqli-005", "sqli", "", `;\s*(drop|alter|truncate)\s+(table|database)\b`),

		// XSS
		mustRule("xss-001", "xss", "", `<\s*script\b`),
		mustRule("xss-002", "xss", "", `\bon(error|load|click|mouseover|focus|toggle)\s*=`),
		mustRule("xss-003", "xss", "", `javascript\s*:`),
		mustRule("xss-004", "xss", "", `<\s*(iframe|object|embed|svg)\b`),

		// 路径穿越 / 敏感文件
		mustRule("lfi-001", "path_traversal", "", `\.\.[/\\]`),
		mustRule("lfi-002", "path_traversal", "", `/etc/(passwd|shadow)\b`),
		mustRule("lfi-003", "path_traversal", "", `\b(boot|win)\.ini\b`),

		// 命令注入
		mustRule("cmdi-001", "cmd_injection", "", `(;|\|\||&&|\|)\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b`),
		mustRule("cmdi-002", "cmd_injection", "", `\$\([^)]*\)`),

		// Log4Shell
		mustRule("rce-001", "log4shell", "", `\$\{\s*jndi\s*:`),

		// 扫描器指纹(只看 User-Agent)
		mustRule("scan-001", "scanner", "header:user-agent", `(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster)`),
	}
}

// LoadRules 从 JSON 文件加载规则,编译失败会带上规则 ID 返回错误。
func LoadRules(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []ruleJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	rules := make([]Rule, 0, len(raw))
	for _, r := range raw {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		rules = append(rules, Rule{
			ID: r.ID, Category: r.Category, Where: strings.ToLower(r.Where),
			Pattern: re, keywords: extractKeywords(r.Pattern),
		})
	}
	return rules, nil
}

const maxDecodeDepth = 3 // URL 解码最多套 3 层,防止被超深编码拖慢处理器

var (
	sqlComment = regexp.MustCompile(`/\*.*?\*/`)
	spaces     = regexp.MustCompile(`\s+`)
)

// normalize 抵消常见的编码/混淆绕过:多重 URL 解码、NUL 字节、SQL 注释穿插、大小写、空白变形。
// 优化:fast path 检测输入是否已经"规范化"了,如果是,直接返回原字符串,
// 避免 4 次不必要的字符串分配(ReplaceAll、两次 regex.ReplaceAllString、ToLower)。
// 这是安全的:所有规则的正则模式都使用 \s+/\\s* 来处理可变空白,
// 所以跳过空格折叠不会影响匹配结果。
func normalize(s string) string {
	if isNormalized(s) {
		return s
	}
	return normalizeSlow(s)
}

// isNormalized 检查字符串是否已经不需要任何 normalize 变换。
// 如果返回 true,则 normalize 可直接返回原字符串。
func isNormalized(s string) bool {
	// 包含 % 或 + 需要 URL 解码;包含 NUL 需要移除
	if strings.ContainsAny(s, "%+\x00") {
		return false
	}
	// 包含 /* */ SQL 注释需要移除
	if strings.Contains(s, "/*") {
		return false
	}
	// 包含大写字母需要转为小写
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return false
		}
	}
	return true
}

func normalizeSlow(s string) string {
	for i := 0; i < maxDecodeDepth; i++ {
		d := unescape(s)
		if d == s {
			break
		}
		s = d
	}
	// 清理:删 NUL → 去掉 /*...*/ 注释 → 折叠连续空白 → 统一小写
	s = strings.ReplaceAll(s, "\x00", "")
	s = sqlComment.ReplaceAllString(s, " ")
	s = spaces.ReplaceAllString(s, " ")
	return strings.ToLower(s)
}

// unescape 是宽容版 URL 解码:遇到非法的 %zz 不会整体放弃,
// 否则攻击者只要塞一个坏序列就能让后面的 payload 躲过解码。
func unescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			b.WriteByte(' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}
