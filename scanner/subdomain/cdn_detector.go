package subdomain

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"moongazing/config"
)

// CDNResult represents CDN detection result
type CDNResult struct {
	Domain      string   `json:"domain"`
	IsCDN       bool     `json:"is_cdn"`
	CDNProvider string   `json:"cdn_provider,omitempty"`
	CDNType     string   `json:"cdn_type,omitempty"` // commercial, cloud, unknown
	IPs         []string `json:"ips"`
	CNAMEs      []string `json:"cnames,omitempty"`
	Headers     []string `json:"cdn_headers,omitempty"`
	RealIPs     []string `json:"real_ips,omitempty"`
	Confidence  int      `json:"confidence"` // 0-100
	Method      string   `json:"method,omitempty"`
}

// CDNDetector handles CDN detection
type CDNDetector struct {
	Timeout     time.Duration
	HTTPClient  *http.Client
	CNAMEMap    map[string]string // CNAME pattern -> CDN name
	HeaderMap   map[string]string // Header name -> CDN name
	IPRanges    map[string][]*net.IPNet
}

// NewCDNDetector creates a new CDN detector
func NewCDNDetector() *CDNDetector {
	return &CDNDetector{
		Timeout: 10 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		CNAMEMap:  loadCNAMEMapFromConfig(),
		HeaderMap: loadHeaderMapFromConfig(),
		IPRanges:  loadIPRangesFromConfig(),
	}
}

// loadCNAMEMapFromConfig loads CNAME patterns from configuration
func loadCNAMEMapFromConfig() map[string]string {
	cdnConfig := config.GetCDNConfig()
	if cdnConfig != nil && len(cdnConfig.CNAMEPatterns) > 0 {
		return cdnConfig.CNAMEPatterns
	}
	// Fallback to minimal defaults
	return map[string]string{
		"cloudflare": "Cloudflare",
		"akamai":     "Akamai",
		"fastly":     "Fastly",
		"cloudfront": "AWS CloudFront",
	}
}

// loadHeaderMapFromConfig loads header patterns from configuration
func loadHeaderMapFromConfig() map[string]string {
	cdnConfig := config.GetCDNConfig()
	if cdnConfig != nil && len(cdnConfig.HeaderPatterns) > 0 {
		return cdnConfig.HeaderPatterns
	}
	// Fallback to minimal defaults
	return map[string]string{
		"cf-ray":      "Cloudflare",
		"x-amz-cf-id": "AWS CloudFront",
	}
}

// loadIPRangesFromConfig loads IP ranges from configuration
func loadIPRangesFromConfig() map[string][]*net.IPNet {
	ranges := make(map[string][]*net.IPNet)
	cdnConfig := config.GetCDNConfig()
	
	if cdnConfig != nil && len(cdnConfig.IPRanges) > 0 {
		for provider, cidrs := range cdnConfig.IPRanges {
			for _, cidr := range cidrs {
				_, ipnet, err := net.ParseCIDR(cidr)
				if err == nil && ipnet != nil {
					ranges[provider] = append(ranges[provider], ipnet)
				}
			}
		}
		if len(ranges) > 0 {
			return ranges
		}
	}
	
	// Fallback to minimal Cloudflare ranges
	defaultRanges := []string{"104.16.0.0/13", "104.24.0.0/14"}
	for _, cidr := range defaultRanges {
		_, ipnet, _ := net.ParseCIDR(cidr)
		if ipnet != nil {
			ranges["Cloudflare"] = append(ranges["Cloudflare"], ipnet)
		}
	}
	return ranges
}

// DetectCDN performs CDN detection for a domain
func (d *CDNDetector) DetectCDN(ctx context.Context, domain string) *CDNResult {
	result := &CDNResult{
		Domain:     domain,
		IsCDN:      false,
		Confidence: 0,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// 1. Check CNAME
	wg.Add(1)
	go func() {
		defer wg.Done()
		cnames, cdnName := d.checkCNAME(domain)
		mu.Lock()
		result.CNAMEs = cnames
		if cdnName != "" {
			result.IsCDN = true
			result.CDNProvider = cdnName
			result.Confidence += 50
			result.Method = "CNAME"
		}
		mu.Unlock()
	}()

	// 2. Check HTTP headers
	wg.Add(1)
	go func() {
		defer wg.Done()
		headers, cdnName := d.checkHeaders(ctx, domain)
		mu.Lock()
		result.Headers = headers
		if cdnName != "" {
			result.IsCDN = true
			if result.CDNProvider == "" {
				result.CDNProvider = cdnName
			}
			result.Confidence += 30
			if result.Method == "" {
				result.Method = "HTTP Header"
			} else {
				result.Method += ",HTTP Header"
			}
		}
		mu.Unlock()
	}()

	// 3. Check IP ranges
	wg.Add(1)
	go func() {
		defer wg.Done()
		ips, cdnName := d.checkIPRange(domain)
		mu.Lock()
		result.IPs = ips
		if cdnName != "" {
			result.IsCDN = true
			if result.CDNProvider == "" {
				result.CDNProvider = cdnName
			}
			result.Confidence += 20
			if result.Method == "" {
				result.Method = "IP Range"
			} else {
				result.Method += ",IP Range"
			}
		}
		mu.Unlock()
	}()

	// 4. Check multiple IPs (multi-region CDN characteristic)
	wg.Add(1)
	go func() {
		defer wg.Done()
		hasMultiIP := d.checkMultipleIPs(domain)
		mu.Lock()
		if hasMultiIP && result.IsCDN {
			result.Confidence += 10
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Cap confidence at 100
	if result.Confidence > 100 {
		result.Confidence = 100
	}

	// Classify CDN type
	if result.CDNProvider != "" {
		result.CDNType = classifyCDNType(result.CDNProvider)
	}

	return result
}

// checkCNAME checks CNAME records for CDN patterns
func (d *CDNDetector) checkCNAME(domain string) ([]string, string) {
	var cnames []string
	var cdnName string

	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != "" {
		cname = strings.TrimSuffix(cname, ".")
		cnames = append(cnames, cname)

		// Check against known CDN patterns
		lowerCname := strings.ToLower(cname)
		for pattern, name := range d.CNAMEMap {
			if strings.Contains(lowerCname, pattern) {
				cdnName = name
				break
			}
		}
	}

	return cnames, cdnName
}

// checkHeaders checks HTTP response headers for CDN signatures
func (d *CDNDetector) checkHeaders(ctx context.Context, domain string) ([]string, string) {
	var cdnHeaders []string
	var cdnName string

	urls := []string{
		"https://" + domain,
		"http://" + domain,
	}

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := d.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check headers
		for header, cdn := range d.HeaderMap {
			parts := strings.SplitN(header, ":", 2)
			headerName := parts[0]
			
			value := resp.Header.Get(headerName)
			if value != "" {
				if len(parts) == 2 {
					// Check header value
					if strings.Contains(strings.ToLower(value), strings.ToLower(strings.TrimSpace(parts[1]))) {
						cdnHeaders = append(cdnHeaders, headerName+": "+value)
						if cdnName == "" {
							cdnName = cdn
						}
					}
				} else {
					cdnHeaders = append(cdnHeaders, headerName+": "+value)
					if cdnName == "" {
						cdnName = cdn
					}
				}
			}
		}

		// Check Server header
		server := resp.Header.Get("Server")
		if server != "" {
			lowerServer := strings.ToLower(server)
			for keyword, cdn := range map[string]string{
				"cloudflare": "Cloudflare",
				"akamaighost": "Akamai",
				"yunjiasu": "百度云加速",
				"upyun": "又拍云CDN",
				"tengine": "阿里云CDN",
			} {
				if strings.Contains(lowerServer, keyword) {
					cdnName = cdn
					break
				}
			}
		}

		if cdnName != "" {
			break
		}
	}

	return cdnHeaders, cdnName
}

// checkIPRange checks if resolved IPs belong to known CDN ranges
func (d *CDNDetector) checkIPRange(domain string) ([]string, string) {
	var ips []string
	var cdnName string

	addrs, err := net.LookupIP(domain)
	if err != nil {
		return ips, cdnName
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ips = append(ips, ipv4.String())

			// Check against known CDN IP ranges
			for cdn, ranges := range d.IPRanges {
				for _, ipnet := range ranges {
					if ipnet.Contains(ipv4) {
						cdnName = cdn
						break
					}
				}
				if cdnName != "" {
					break
				}
			}
		}
	}

	return ips, cdnName
}

// checkMultipleIPs checks if domain resolves to multiple IPs (CDN characteristic)
func (d *CDNDetector) checkMultipleIPs(domain string) bool {
	addrs, err := net.LookupIP(domain)
	if err != nil {
		return false
	}

	// Count unique IPv4 addresses
	uniqueIPs := make(map[string]bool)
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			uniqueIPs[ipv4.String()] = true
		}
	}

	return len(uniqueIPs) >= 2
}

// classifyCDNType classifies CDN provider type
func classifyCDNType(provider string) string {
	cloudCDNs := []string{
		"阿里云", "腾讯云", "华为云", "百度云", "京东云", "UCloud", "七牛云", "又拍云", "金山云",
		"AWS", "Azure", "Google Cloud",
	}
	
	for _, cloud := range cloudCDNs {
		if strings.Contains(provider, cloud) {
			return "cloud"
		}
	}
	
	commercialCDNs := []string{
		"Cloudflare", "Akamai", "Fastly", "网宿", "蓝汛", "帝联",
		"Imperva", "Sucuri", "StackPath", "Edgecast",
	}
	
	for _, commercial := range commercialCDNs {
		if strings.Contains(provider, commercial) {
			return "commercial"
		}
	}
	
	return "unknown"
}

// TryFindRealIP attempts to find the real IP behind CDN
func (d *CDNDetector) TryFindRealIP(ctx context.Context, domain string) []string {
	var realIPs []string
	seen := make(map[string]bool)

	// Common subdomains that might expose real IP
	subdomains := []string{
		"direct", "origin", "real", "backend", "server",
		"ftp", "mail", "smtp", "pop", "imap",
		"cpanel", "webmail", "admin", "manage",
		"direct-connect", "origin-www",
		"old", "dev", "test", "staging",
		"vpn", "ssh", "rdp", "remote",
	}

	// Also try common record types
	for _, sub := range subdomains {
		fullDomain := sub + "." + domain
		ips, err := net.LookupIP(fullDomain)
		if err != nil {
			continue
		}

		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				ipStr := ipv4.String()
				if !seen[ipStr] && !d.isKnownCDNIP(ipStr) {
					seen[ipStr] = true
					realIPs = append(realIPs, ipStr)
				}
			}
		}
	}

	// Try historical DNS records (would need external API)
	// Try SSL certificate check (would need external API)
	// Try zone transfer if possible

	return realIPs
}

// isKnownCDNIP checks if an IP belongs to known CDN ranges
func (d *CDNDetector) isKnownCDNIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ranges := range d.IPRanges {
		for _, ipnet := range ranges {
			if ipnet.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}

// BatchDetectCDN detects CDN for multiple domains
func (d *CDNDetector) BatchDetectCDN(ctx context.Context, domains []string, concurrency int) []*CDNResult {
	if concurrency <= 0 {
		concurrency = 10
	}

	results := make([]*CDNResult, len(domains))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	var mu sync.Mutex

	for i, domain := range domains {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int, dom string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := d.DetectCDN(ctx, dom)
			
			// Try to find real IP if CDN detected
			if result.IsCDN {
				result.RealIPs = d.TryFindRealIP(ctx, dom)
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, domain)
	}

	wg.Wait()
	return results
}

// IsCDNIP checks if a single IP is a known CDN IP
func (d *CDNDetector) IsCDNIP(ip string) (bool, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, ""
	}

	for cdn, ranges := range d.IPRanges {
		for _, ipnet := range ranges {
			if ipnet.Contains(parsedIP) {
				return true, cdn
			}
		}
	}

	// Check if IP has CDN-like reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil {
		for _, name := range names {
			lowerName := strings.ToLower(name)
			for pattern, cdn := range d.CNAMEMap {
				if strings.Contains(lowerName, pattern) {
					return true, cdn
				}
			}
		}
	}

	return false, ""
}

// GetCDNProviders returns list of known CDN providers
func GetCDNProviders() []string {
	seen := make(map[string]bool)
	var providers []string

	cnameMap := loadCNAMEMapFromConfig()
	for _, provider := range cnameMap {
		if !seen[provider] {
			seen[provider] = true
			providers = append(providers, provider)
		}
	}

	return providers
}

// ASNInfo represents ASN information
type ASNInfo struct {
	ASN         string `json:"asn"`
	Provider    string `json:"provider"`
	Description string `json:"description"`
}

// Common CDN ASNs (simplified)
var CDNASNs = map[string]ASNInfo{
	"AS13335": {ASN: "AS13335", Provider: "Cloudflare", Description: "Cloudflare, Inc."},
	"AS16509": {ASN: "AS16509", Provider: "Amazon", Description: "Amazon.com, Inc. (AWS)"},
	"AS14618": {ASN: "AS14618", Provider: "Amazon", Description: "Amazon.com, Inc. (AWS)"},
	"AS20940": {ASN: "AS20940", Provider: "Akamai", Description: "Akamai International B.V."},
	"AS16625": {ASN: "AS16625", Provider: "Akamai", Description: "Akamai Technologies, Inc."},
	"AS54113": {ASN: "AS54113", Provider: "Fastly", Description: "Fastly, Inc."},
	"AS8075":  {ASN: "AS8075", Provider: "Microsoft", Description: "Microsoft Corporation (Azure)"},
	"AS15169": {ASN: "AS15169", Provider: "Google", Description: "Google LLC"},
	"AS37963": {ASN: "AS37963", Provider: "Alibaba", Description: "Alibaba (China) Technology Co., Ltd."},
	"AS45102": {ASN: "AS45102", Provider: "Alibaba", Description: "Alibaba (US) Technology Co., Ltd."},
	"AS132203": {ASN: "AS132203", Provider: "Tencent", Description: "Tencent Building, Kejizhongyi Avenue"},
}

// DetectCDNByRegex uses regex patterns to detect CDN from various sources
var CDNRegexPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)cloudflare`),
	regexp.MustCompile(`(?i)akamai`),
	regexp.MustCompile(`(?i)fastly`),
	regexp.MustCompile(`(?i)cloudfront`),
	regexp.MustCompile(`(?i)azure(cdn|edge|fd)`),
	regexp.MustCompile(`(?i)(ali|aliyun|kunlun)`),
	regexp.MustCompile(`(?i)(tencent|qcloud)`),
	regexp.MustCompile(`(?i)wangsu|wscdn|chinanetcenter`),
	regexp.MustCompile(`(?i)chinacache`),
	regexp.MustCompile(`(?i)upyun`),
	regexp.MustCompile(`(?i)qiniu|qbox`),
	regexp.MustCompile(`(?i)baiduyun|yunjiasu`),
	regexp.MustCompile(`(?i)huawei|hwcdn`),
}
