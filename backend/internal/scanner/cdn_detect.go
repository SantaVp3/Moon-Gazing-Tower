package scanner

import (
	"net"
	"strings"
)

// CDNDetector CDN检测器
type CDNDetector struct {
	cdnCNAMEs []string
	cdnIPs    []string
}

// NewCDNDetector 创建CDN检测器
func NewCDNDetector() *CDNDetector {
	return &CDNDetector{
		cdnCNAMEs: []string{
			"cloudfront.net",
			"cloudflare.com",
			"akamai.net",
			"fastly.net",
			"cdn77.com",
			"incapdns.net",
			"amazonaws.com",
			"azureedge.net",
			"chinacache.net",
			"cdn.aliyuncs.com",
			"kunlun",
			"cdn.jsdelivr.net",
			"cdnify.com",
			"wscdns.com",
			"wscloudcdn.com",
		},
		cdnIPs: []string{
			// Cloudflare IP ranges (部分)
			"103.21.244.",
			"103.22.200.",
			"103.31.4.",
			"104.16.",
			"104.17.",
			"104.18.",
			"104.19.",
			"104.20.",
			"104.21.",
			"104.22.",
			"104.23.",
			"104.24.",
			"104.25.",
			"104.26.",
			"104.27.",
			"104.28.",
			"104.29.",
			"104.30.",
			"104.31.",
			"172.64.",
			"172.65.",
			"172.66.",
			"172.67.",
			"172.68.",
			"172.69.",
			"172.70.",
			"172.71.",
			// Akamai (部分)
			"23.32.",
			"23.33.",
			"23.34.",
			"23.35.",
			"23.36.",
			"23.37.",
			"23.38.",
			"23.39.",
			// Fastly (部分)
			"151.101.",
			"199.27.",
		},
	}
}

// IsCDN 检测是否为CDN
func (d *CDNDetector) IsCDN(domain string) bool {
	// 检查CNAME
	if d.checkCNAME(domain) {
		return true
	}

	// 检查IP
	if d.checkIP(domain) {
		return true
	}

	return false
}

// checkCNAME 检查CNAME记录
func (d *CDNDetector) checkCNAME(domain string) bool {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return false
	}

	cname = strings.ToLower(cname)
	for _, cdnCNAME := range d.cdnCNAMEs {
		if strings.Contains(cname, cdnCNAME) {
			return true
		}
	}

	return false
}

// checkIP 检查IP地址
func (d *CDNDetector) checkIP(domain string) bool {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return false
	}

	// 如果有多个不同C段的IP，很可能是CDN
	if len(ips) >= 3 {
		cBlocks := make(map[string]bool)
		for _, ip := range ips {
			parts := strings.Split(ip, ".")
			if len(parts) == 4 {
				cBlock := parts[0] + "." + parts[1] + "." + parts[2]
				cBlocks[cBlock] = true
			}
		}
		if len(cBlocks) >= 3 {
			return true
		}
	}

	// 检查IP是否在已知CDN范围内
	for _, ip := range ips {
		for _, cdnIP := range d.cdnIPs {
			if strings.HasPrefix(ip, cdnIP) {
				return true
			}
		}
	}

	return false
}

// GetCDNName 获取CDN名称
func (d *CDNDetector) GetCDNName(domain string) string {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return ""
	}

	cname = strings.ToLower(cname)
	cdnNames := map[string]string{
		"cloudfront.net":   "CloudFront",
		"cloudflare.com":   "Cloudflare",
		"akamai.net":       "Akamai",
		"fastly.net":       "Fastly",
		"cdn77.com":        "CDN77",
		"incapdns.net":     "Incapsula",
		"amazonaws.com":    "AWS",
		"azureedge.net":    "Azure CDN",
		"chinacache.net":   "ChinaCache",
		"cdn.aliyuncs.com": "阿里云CDN",
		"cdn.jsdelivr.net": "jsDelivr",
	}

	for key, name := range cdnNames {
		if strings.Contains(cname, key) {
			return name
		}
	}

	// 根据IP检测
	ips, err := net.LookupHost(domain)
	if err == nil {
		for _, ip := range ips {
			if strings.HasPrefix(ip, "104.") || strings.HasPrefix(ip, "172.") {
				return "Cloudflare"
			}
			if strings.HasPrefix(ip, "23.") {
				return "Akamai"
			}
			if strings.HasPrefix(ip, "151.101.") || strings.HasPrefix(ip, "199.27.") {
				return "Fastly"
			}
		}
	}

	return "Unknown CDN"
}
