package core

import (
	"regexp"
	"strings"
)

// 二级域名后缀列表（需要特殊处理的后缀）
var secondLevelTLDs = map[string]bool{
	// 中国
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"edu.cn": true, "ac.cn": true, "mil.cn": true,
	// 香港
	"com.hk": true, "org.hk": true, "net.hk": true, "gov.hk": true, "edu.hk": true,
	// 台湾
	"com.tw": true, "org.tw": true, "net.tw": true, "gov.tw": true, "edu.tw": true,
	// 日本
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true, "go.jp": true,
	// 韩国
	"co.kr": true, "or.kr": true, "ne.kr": true, "go.kr": true,
	// 英国
	"co.uk": true, "org.uk": true, "me.uk": true, "gov.uk": true, "ac.uk": true,
	// 澳大利亚
	"com.au": true, "net.au": true, "org.au": true, "gov.au": true, "edu.au": true,
	// 新西兰
	"co.nz": true, "org.nz": true, "net.nz": true, "govt.nz": true,
	// 巴西
	"com.br": true, "org.br": true, "net.br": true, "gov.br": true,
	// 印度
	"co.in": true, "org.in": true, "net.in": true, "gov.in": true,
	// 俄罗斯
	"com.ru": true, "org.ru": true, "net.ru": true,
	// 其他常见
	"com.sg": true, "org.sg": true, "gov.sg": true,
	"com.my": true, "org.my": true, "gov.my": true,
	"com.ph": true, "org.ph": true, "gov.ph": true,
	"com.vn": true, "org.vn": true, "gov.vn": true,
	"co.th": true, "or.th": true, "go.th": true,
	"co.id": true, "or.id": true, "go.id": true,
}

// ExtractRootDomain 从完整域名中提取根域名
// 例如: www.example.com.cn -> example.com.cn
//
//	api.test.example.com -> example.com
func ExtractRootDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	// 检查是否是二级后缀
	if len(parts) >= 3 {
		possibleTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if secondLevelTLDs[possibleTLD] {
			return parts[len(parts)-3] + "." + possibleTLD
		}
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// ExtractTitle extracts title from HTML
func ExtractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Limit title length
		if len(title) > 100 {
			title = title[:100] + "..."
		}
		return title
	}
	return ""
}
