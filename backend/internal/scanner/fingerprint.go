package scanner

import (
	"log"
	"regexp"
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// Fingerprint 指纹信息
type Fingerprint struct {
	Name     string
	Category string
	Rules    []FingerprintRule
}

// FingerprintRule 指纹规则
type FingerprintRule struct {
	Type    string // header, body, title, server, cookie
	Pattern string
	Match   *regexp.Regexp
}

// FingerprintDB 指纹数据库
var FingerprintDB = []Fingerprint{
	// Web服务器
	{
		Name:     "Nginx",
		Category: "WebServer",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "nginx"},
			{Type: "header", Pattern: "X-Powered-By.*nginx"},
		},
	},
	{
		Name:     "Apache",
		Category: "WebServer",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "Apache"},
			{Type: "header", Pattern: "X-Powered-By.*Apache"},
		},
	},
	{
		Name:     "IIS",
		Category: "WebServer",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "Microsoft-IIS"},
			{Type: "header", Pattern: "X-AspNet-Version"},
		},
	},
	// CMS
	{
		Name:     "WordPress",
		Category: "CMS",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "wp-content"},
			{Type: "body", Pattern: "wp-includes"},
			{Type: "body", Pattern: "/wp-json/"},
		},
	},
	{
		Name:     "Joomla",
		Category: "CMS",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "/components/com_"},
			{Type: "body", Pattern: "Joomla!"},
		},
	},
	{
		Name:     "Drupal",
		Category: "CMS",
		Rules: []FingerprintRule{
			{Type: "header", Pattern: "X-Drupal-Cache"},
			{Type: "header", Pattern: "X-Generator.*Drupal"},
			{Type: "body", Pattern: "Drupal.settings"},
		},
	},
	// 框架
	{
		Name:     "Laravel",
		Category: "Framework",
		Rules: []FingerprintRule{
			{Type: "cookie", Pattern: "laravel_session"},
			{Type: "header", Pattern: "X-Powered-By.*Laravel"},
		},
	},
	{
		Name:     "Spring Boot",
		Category: "Framework",
		Rules: []FingerprintRule{
			{Type: "header", Pattern: "X-Application-Context"},
			{Type: "body", Pattern: "Whitelabel Error Page"},
		},
	},
	{
		Name:     "Django",
		Category: "Framework",
		Rules: []FingerprintRule{
			{Type: "cookie", Pattern: "csrftoken"},
			{Type: "cookie", Pattern: "sessionid"},
			{Type: "header", Pattern: "X-Frame-Options.*DENY"},
		},
	},
	{
		Name:     "Flask",
		Category: "Framework",
		Rules: []FingerprintRule{
			{Type: "cookie", Pattern: "session"},
			{Type: "header", Pattern: "Server.*Werkzeug"},
		},
	},
	{
		Name:     "Express",
		Category: "Framework",
		Rules: []FingerprintRule{
			{Type: "header", Pattern: "X-Powered-By.*Express"},
		},
	},
	// 中间件
	{
		Name:     "Tomcat",
		Category: "Middleware",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "Apache-Coyote"},
			{Type: "cookie", Pattern: "JSESSIONID"},
			{Type: "body", Pattern: "Apache Tomcat"},
		},
	},
	{
		Name:     "WebLogic",
		Category: "Middleware",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "WebLogic"},
			{Type: "body", Pattern: "Error 404--Not Found"},
		},
	},
	{
		Name:     "JBoss",
		Category: "Middleware",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "JBoss"},
			{Type: "body", Pattern: "JBoss"},
		},
	},
	// CDN
	{
		Name:     "Cloudflare",
		Category: "CDN",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "cloudflare"},
			{Type: "header", Pattern: "CF-RAY"},
			{Type: "header", Pattern: "cf-cache-status"},
		},
	},
	{
		Name:     "Akamai",
		Category: "CDN",
		Rules: []FingerprintRule{
			{Type: "header", Pattern: "X-Akamai"},
			{Type: "header", Pattern: "Akamai"},
		},
	},
	// WAF
	{
		Name:     "ModSecurity",
		Category: "WAF",
		Rules: []FingerprintRule{
			{Type: "server", Pattern: "Mod_Security"},
			{Type: "server", Pattern: "NOYB"},
		},
	},
	{
		Name:     "Cloudflare WAF",
		Category: "WAF",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "Attention Required! \\| Cloudflare"},
		},
	},
	// JavaScript框架
	{
		Name:     "React",
		Category: "JavaScript",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "react"},
			{Type: "body", Pattern: "_react"},
		},
	},
	{
		Name:     "Vue.js",
		Category: "JavaScript",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "vue"},
			{Type: "body", Pattern: "data-v-"},
		},
	},
	{
		Name:     "Angular",
		Category: "JavaScript",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "ng-version"},
			{Type: "body", Pattern: "angular"},
		},
	},
	{
		Name:     "jQuery",
		Category: "JavaScript",
		Rules: []FingerprintRule{
			{Type: "body", Pattern: "jquery"},
		},
	},
}

// InitFingerprints 初始化指纹规则
func InitFingerprints() {
	for i := range FingerprintDB {
		for j := range FingerprintDB[i].Rules {
			FingerprintDB[i].Rules[j].Match = regexp.MustCompile("(?i)" + FingerprintDB[i].Rules[j].Pattern)
		}
	}
}

// MatchFingerprints 匹配指纹（同时支持内置和数据库指纹）
func MatchFingerprints(headers map[string]string, body, title string) []string {
	matched := make(map[string]bool)
	var fingerprints []string

	// 匹配内置指纹
	for _, fp := range FingerprintDB {
		for _, rule := range fp.Rules {
			var content string
			switch rule.Type {
			case "server":
				content = headers["Server"]
			case "header":
				// 检查所有header
				for k, v := range headers {
					content += k + ": " + v + "\n"
				}
			case "body":
				content = body
			case "title":
				content = title
			case "cookie":
				content = headers["Set-Cookie"]
			}

			if rule.Match != nil && rule.Match.MatchString(content) {
				if !matched[fp.Name] {
					matched[fp.Name] = true
					fingerprints = append(fingerprints, fp.Name)
				}
				break
			}
		}
	}

	// 从数据库加载并匹配自定义指纹
	var dbFingerprints []models.Fingerprint
	if err := database.DB.Where("is_enabled = ?", true).Find(&dbFingerprints).Error; err != nil {
		log.Printf("Failed to load fingerprints from database: %v", err)
	} else {
		for _, dbFp := range dbFingerprints {
			if matchDatabaseFingerprint(dbFp, headers, body, title) {
				if !matched[dbFp.Name] {
					matched[dbFp.Name] = true
					fingerprints = append(fingerprints, dbFp.Name)
				}
			}
		}
	}

	return fingerprints
}

// matchDatabaseFingerprint 匹配数据库指纹
func matchDatabaseFingerprint(fp models.Fingerprint, headers map[string]string, body, title string) bool {
	// 遍历所有 DSL 规则，任意一个匹配即可
	for _, dslRule := range fp.DSL {
		if matchDSLRule(dslRule, headers, body, title) {
			return true
		}
	}
	return false
}

// matchDSLRule 匹配单个 DSL 规则
func matchDSLRule(rule string, headers map[string]string, body, title string) bool {
	// 解析 DSL 规则，例如: contains(body, 'keyword')
	rule = strings.TrimSpace(rule)
	
	// 提取函数名和参数
	if strings.HasPrefix(rule, "contains(") && strings.HasSuffix(rule, ")") {
		// 提取参数: contains(target, 'keyword')
		params := rule[9 : len(rule)-1] // 去掉 "contains(" 和 ")"
		parts := parseParams(params)
		
		if len(parts) != 2 {
			log.Printf("Invalid DSL rule format: %s", rule)
			return false
		}
		
		target := strings.TrimSpace(parts[0])
		keyword := strings.Trim(strings.TrimSpace(parts[1]), "'\"")
		
		// 获取目标内容
		var content string
		switch target {
		case "body":
			content = body
		case "title":
			content = title
		case "header":
			for k, v := range headers {
				content += k + ": " + v + "\n"
			}
		default:
			// 尝试作为具体的 header 字段
			if headerValue, ok := headers[target]; ok {
				content = headerValue
			}
		}
		
		// 检查是否包含关键词（不区分大小写）
		return strings.Contains(strings.ToLower(content), strings.ToLower(keyword))
	}
	
	// 其他 DSL 函数可以在这里扩展
	log.Printf("Unsupported DSL rule: %s", rule)
	return false
}

// parseParams 解析 DSL 参数（处理引号内的逗号）
func parseParams(params string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)
	
	for _, ch := range params {
		if (ch == '\'' || ch == '"') {
			if inQuotes && ch == quoteChar {
				inQuotes = false
			} else if !inQuotes {
				inQuotes = true
				quoteChar = ch
			}
			current.WriteRune(ch)
		} else if ch == ',' && !inQuotes {
			result = append(result, current.String())
			current.Reset()
		} else {
			current.WriteRune(ch)
		}
	}
	
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	
	return result
}

// DetectTechnology 检测技术栈
func DetectTechnology(headers map[string]string, body string) map[string][]string {
	result := make(map[string][]string)

	// 按类别组织
	for _, fp := range FingerprintDB {
		for _, rule := range fp.Rules {
			var content string
			switch rule.Type {
			case "server":
				content = headers["Server"]
			case "header":
				for k, v := range headers {
					content += k + ": " + v + "\n"
				}
			case "body":
				content = body
			case "cookie":
				content = headers["Set-Cookie"]
			}

			if rule.Match != nil && rule.Match.MatchString(content) {
				result[fp.Category] = append(result[fp.Category], fp.Name)
				break
			}
		}
	}

	// 去重
	for category, techs := range result {
		result[category] = uniqueStrings(techs)
	}

	return result
}

// uniqueStrings 字符串数组去重
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// ExtractTitle 提取HTML标题
func ExtractTitle(body string) string {
	titleRegex := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// IsCDN 判断是否为CDN
func IsCDN(headers map[string]string, ip string) bool {
	// 检查CDN特征头
	cdnHeaders := []string{
		"CF-RAY",           // Cloudflare
		"X-Akamai",         // Akamai
		"X-CDN",            // 通用CDN
		"X-Cache",          // 缓存
		"Via",              // 代理
		"X-Served-By",      // CDN服务器
		"X-Fastly-Request-ID", // Fastly
	}

	for _, h := range cdnHeaders {
		if _, exists := headers[h]; exists {
			return true
		}
	}

	// 检查Server头中的CDN标识
	server := strings.ToLower(headers["Server"])
	cdnKeywords := []string{"cloudflare", "akamai", "cdn", "fastly", "cloudfront"}
	for _, keyword := range cdnKeywords {
		if strings.Contains(server, keyword) {
			return true
		}
	}

	return false
}

// ExtractIPFromURL 从URL中提取IP地址
func ExtractIPFromURL(urlStr string) string {
	// 匹配 scheme://ip:port 格式
	ipPortRegex := regexp.MustCompile(`^https?://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?::[0-9]+)?`)
	matches := ipPortRegex.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	
	// 如果是域名，返回空字符串（可以后续通过DNS查询获取）
	return ""
}
