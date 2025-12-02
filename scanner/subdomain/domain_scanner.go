package subdomain

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"moongazing/config"
	"moongazing/scanner/core"
)

// SubdomainResult represents a discovered subdomain
type SubdomainResult struct {
	Subdomain   string   `json:"subdomain"`
	Domain      string   `json:"domain"`
	FullDomain  string   `json:"full_domain"`
	IPs         []string `json:"ips,omitempty"`
	CNAMEs      []string `json:"cnames,omitempty"`
	Alive       bool     `json:"alive"`
	HTTPStatus  int      `json:"http_status,omitempty"`
	HTTPSStatus int      `json:"https_status,omitempty"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	CDN         bool     `json:"cdn"`
	CDNProvider string   `json:"cdn_provider,omitempty"`
	Fingerprint []string `json:"fingerprint,omitempty"`
	ContentLen  int64    `json:"content_length,omitempty"`
}

// DomainScanResult represents the result of domain scanning
type DomainScanResult struct {
	Domain       string            `json:"domain"`
	TotalChecked int               `json:"total_checked"`
	Found        int               `json:"found"`
	StartTime    time.Time         `json:"start_time"`
	EndTime      time.Time         `json:"end_time"`
	Duration     string            `json:"duration"`
	Subdomains   []SubdomainResult `json:"subdomains"`
	NSRecords    []string          `json:"ns_records,omitempty"`
	MXRecords    []string          `json:"mx_records,omitempty"`
	TXTRecords   []string          `json:"txt_records,omitempty"`
}

// DomainInfo represents basic domain information
type DomainInfo struct {
	Domain     string   `json:"domain"`
	IPs        []string `json:"ips"`
	CNAMEs     []string `json:"cnames"`
	NSRecords  []string `json:"ns_records"`
	MXRecords  []string `json:"mx_records"`
	TXTRecords []string `json:"txt_records"`
	SOARecord  string   `json:"soa_record,omitempty"`
}

// DomainScanner handles domain scanning and subdomain enumeration
type DomainScanner struct {
	Timeout      time.Duration
	Concurrency  int
	Resolvers    []string
	EnableHTTP   bool // 是否启用HTTP探测（会变慢但获取更多信息）
	WildcardIPs  map[string]bool // 泛解析IP记录
}

// NewDomainScanner creates a new domain scanner
func NewDomainScanner(concurrency int) *DomainScanner {
	if concurrency == 0 {
		concurrency = 200 // 提高默认并发数，DNS查询很快
	}
	return &DomainScanner{
		Timeout:     2 * time.Second,
		Concurrency: concurrency,
		EnableHTTP:  false, // 默认不启用HTTP探测以提高速度
		Resolvers: []string{
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
			"114.114.114.114:53",
			"223.5.5.5:53",
			"119.29.29.29:53",  // DNSPod
			"180.76.76.76:53", // 百度DNS
		},
		WildcardIPs: make(map[string]bool),
	}
}

// NewDomainScannerWithHTTP creates a scanner with HTTP probing enabled
func NewDomainScannerWithHTTP(concurrency int) *DomainScanner {
	scanner := NewDomainScanner(concurrency)
	scanner.EnableHTTP = true
	scanner.Concurrency = 50 // HTTP探测需要降低并发
	return scanner
}

// GetSubdomainWordlist returns subdomain wordlist from config
func GetSubdomainWordlist() []string {
	wordlist := config.GetSubdomains()
	if len(wordlist) == 0 {
		// Fallback to minimal built-in list if config not loaded
		return []string{"www", "mail", "ftp", "admin", "api", "dev", "test", "blog", "shop", "m"}
	}
	return wordlist
}

// GetDomainInfo retrieves DNS information for a domain
func (s *DomainScanner) GetDomainInfo(ctx context.Context, domain string) *DomainInfo {
	info := &DomainInfo{
		Domain: domain,
	}

	// A records
	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				info.IPs = append(info.IPs, ipv4.String())
			}
		}
	}

	// CNAME records
	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != "" && cname != domain+"." {
		info.CNAMEs = append(info.CNAMEs, strings.TrimSuffix(cname, "."))
	}

	// NS records
	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nsRecords {
			info.NSRecords = append(info.NSRecords, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// MX records
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			info.MXRecords = append(info.MXRecords, fmt.Sprintf("%s (priority: %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	}

	// TXT records
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		info.TXTRecords = txtRecords
	}

	return info
}

// CheckSubdomain checks if a subdomain exists (DNS only for speed)
func (s *DomainScanner) CheckSubdomain(ctx context.Context, subdomain, domain string) *SubdomainResult {
	fullDomain := subdomain + "." + domain
	result := &SubdomainResult{
		Subdomain:  subdomain,
		Domain:     domain,
		FullDomain: fullDomain,
		Alive:      false,
	}

	// DNS查询使用自定义resolver和超时
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: s.Timeout,
			}
			// 随机选择一个DNS服务器
			resolverAddr := s.Resolvers[time.Now().UnixNano()%int64(len(s.Resolvers))]
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}

	// 设置查询超时
	queryCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	// Try to resolve the domain
	ips, err := resolver.LookupIP(queryCtx, "ip4", fullDomain)
	if err != nil {
		return result
	}

	if len(ips) == 0 {
		return result
	}

	result.Alive = true
	for _, ip := range ips {
		ipStr := ip.String()
		result.IPs = append(result.IPs, ipStr)
	}

	// 检查是否命中泛解析IP
	if s.isWildcardIP(result.IPs) {
		result.Alive = false
		return result
	}

	// Try to get CNAME (使用新的resolver)
	cname, err := resolver.LookupCNAME(queryCtx, fullDomain)
	if err == nil && cname != "" && cname != fullDomain+"." {
		result.CNAMEs = append(result.CNAMEs, strings.TrimSuffix(cname, "."))
	}

	// Check for CDN based on CNAME and IP
	result.CDN, result.CDNProvider = s.detectCDN(result.CNAMEs, result.IPs)

	// HTTP probe only if enabled (for detailed info)
	if s.EnableHTTP {
		s.httpProbe(ctx, result)
	}

	return result
}

// isWildcardIP checks if IPs match wildcard DNS records
func (s *DomainScanner) isWildcardIP(ips []string) bool {
	if len(s.WildcardIPs) == 0 {
		return false
	}
	for _, ip := range ips {
		if s.WildcardIPs[ip] {
			return true
		}
	}
	return false
}

// detectWildcardDNS detects wildcard DNS for a domain
func (s *DomainScanner) detectWildcardDNS(ctx context.Context, domain string) {
	s.WildcardIPs = make(map[string]bool)
	
	// 生成随机子域名测试泛解析
	testSubdomains := []string{
		generateRandomString(8),
		generateRandomString(10),
		generateRandomString(12),
	}
	
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: s.Timeout}
			resolverAddr := s.Resolvers[0]
			return d.DialContext(ctx, "udp", resolverAddr)
		},
	}
	
	wildcardCount := 0
	for _, sub := range testSubdomains {
		testDomain := sub + "." + domain
		queryCtx, cancel := context.WithTimeout(ctx, s.Timeout)
		ips, err := resolver.LookupIP(queryCtx, "ip4", testDomain)
		cancel()
		
		if err == nil && len(ips) > 0 {
			wildcardCount++
			for _, ip := range ips {
				s.WildcardIPs[ip.String()] = true
			}
		}
	}
	
	// 如果3个随机子域名都有解析，认为存在泛解析
	if wildcardCount < 2 {
		s.WildcardIPs = make(map[string]bool) // 清空，不是泛解析
	}
}

// generateRandomString generates a random string for wildcard detection
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(time.Nanosecond) // 确保随机性
	}
	return string(b)
}

// httpProbe performs HTTP/HTTPS probing to get title, status code, etc.
func (s *DomainScanner) httpProbe(ctx context.Context, result *SubdomainResult) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Try HTTPS first
	httpsURL := "https://" + result.FullDomain
	if resp, err := s.doHTTPRequest(ctx, client, httpsURL); err == nil {
		result.HTTPSStatus = resp.StatusCode
		if result.HTTPStatus == 0 {
			result.HTTPStatus = resp.StatusCode
		}
		s.parseHTTPResponse(resp, result)
		resp.Body.Close()
	}

	// Try HTTP
	httpURL := "http://" + result.FullDomain
	if resp, err := s.doHTTPRequest(ctx, client, httpURL); err == nil {
		result.HTTPStatus = resp.StatusCode
		if result.Title == "" {
			s.parseHTTPResponse(resp, result)
		}
		resp.Body.Close()
	}
}

// doHTTPRequest makes an HTTP request with context
func (s *DomainScanner) doHTTPRequest(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return client.Do(req)
}

// parseHTTPResponse extracts information from HTTP response
func (s *DomainScanner) parseHTTPResponse(resp *http.Response, result *SubdomainResult) {
	// Get Server header
	if server := resp.Header.Get("Server"); server != "" {
		result.Server = server
		// Add to fingerprint
		result.Fingerprint = append(result.Fingerprint, server)
	}

	// Get X-Powered-By
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		result.Fingerprint = append(result.Fingerprint, poweredBy)
	}

	// Read body for title (limit to 64KB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err == nil {
		result.ContentLen = int64(len(body))
		
		// Extract title
		if title := core.ExtractTitle(string(body)); title != "" {
			result.Title = title
		}
		
		// Simple fingerprint detection from body
		bodyStr := strings.ToLower(string(body))
		fingerprints := detectFingerprints(bodyStr, resp.Header)
		result.Fingerprint = append(result.Fingerprint, fingerprints...)
	}

	// Remove duplicates from fingerprint
	result.Fingerprint = uniqueStrings(result.Fingerprint)
}


// detectFingerprints detects web technologies from response
func detectFingerprints(body string, headers http.Header) []string {
	var fps []string
	
	// Common frameworks/technologies
	patterns := map[string][]string{
		"WordPress":   {"wp-content", "wp-includes", "wordpress"},
		"Drupal":      {"drupal", "sites/all", "sites/default"},
		"Joomla":      {"joomla", "/components/com_"},
		"ThinkPHP":    {"thinkphp", "think\\"},
		"Laravel":     {"laravel", "laravel_session"},
		"Spring":      {"spring", "j_spring_security"},
		"React":       {"react", "_react", "reactroot"},
		"Vue.js":      {"vue.js", "vue.min.js", "__vue__"},
		"Angular":     {"angular", "ng-version"},
		"jQuery":      {"jquery"},
		"Bootstrap":   {"bootstrap"},
		"Nginx":       {"nginx"},
		"Apache":      {"apache"},
		"IIS":         {"iis", "asp.net"},
		"Tomcat":      {"tomcat", "catalina"},
		"WebLogic":    {"weblogic"},
		"phpMyAdmin":  {"phpmyadmin"},
		"Confluence":  {"confluence"},
		"JIRA":        {"jira"},
		"GitLab":      {"gitlab"},
		"Jenkins":     {"jenkins"},
	}
	
	for tech, keywords := range patterns {
		for _, kw := range keywords {
			if strings.Contains(body, kw) {
				fps = append(fps, tech)
				break
			}
		}
	}
	
	// Check headers for tech
	if setCookie := headers.Get("Set-Cookie"); setCookie != "" {
		setCookieLower := strings.ToLower(setCookie)
		if strings.Contains(setCookieLower, "phpsessid") {
			fps = append(fps, "PHP")
		}
		if strings.Contains(setCookieLower, "jsessionid") {
			fps = append(fps, "Java")
		}
		if strings.Contains(setCookieLower, "asp.net") {
			fps = append(fps, "ASP.NET")
		}
	}
	
	return fps
}

// detectCDN detects if the domain is using a CDN
func (s *DomainScanner) detectCDN(cnames []string, ips []string) (bool, string) {
	// CDN CNAME patterns
	cdnPatterns := map[string][]string{
		"Cloudflare":    {"cloudflare", "cdn.cloudflare"},
		"Akamai":        {"akamai", "akamaitechnologies", "edgekey", "edgesuite"},
		"Fastly":        {"fastly", "fastlylb"},
		"CloudFront":    {"cloudfront.net", "awsglobalaccelerator"},
		"Azure CDN":     {"azureedge.net", "msecnd.net"},
		"Google CDN":    {"googleusercontent", "googleapis", "gstatic"},
		"阿里云CDN":     {"alicdn", "aliyuncs", "kunlun"},
		"腾讯云CDN":     {"qcloud", "myqcloud", "cdntip"},
		"百度云CDN":     {"bdimg", "baidubce", "bcebos"},
		"网宿CDN":       {"wscdns", "wsdvs", "wsglb"},
		"七牛CDN":       {"qiniudns", "qbox"},
		"又拍云CDN":     {"upai", "upaiyun"},
		"Imperva":       {"incapdns", "imperva"},
		"StackPath":     {"stackpathdns", "highwinds"},
		"KeyCDN":        {"keycdn"},
		"Sucuri":        {"sucuri"},
		"Verizon":       {"edgecast"},
	}
	
	// Check CNAMEs
	for _, cname := range cnames {
		cnameLower := strings.ToLower(cname)
		for provider, patterns := range cdnPatterns {
			for _, pattern := range patterns {
				if strings.Contains(cnameLower, pattern) {
					return true, provider
				}
			}
		}
	}
	
	// Check IP ranges for known CDN providers
	for _, ip := range ips {
		if provider := checkCDNByIP(ip); provider != "" {
			return true, provider
		}
	}
	
	return false, ""
}

// checkCDNByIP checks if IP belongs to known CDN ranges
func checkCDNByIP(ip string) string {
	// Cloudflare IP ranges (simplified check)
	cloudflareRanges := []string{
		"103.21.", "103.22.", "103.31.", "104.16.", "104.17.", "104.18.",
		"104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.",
		"104.25.", "104.26.", "104.27.", "108.162.", "131.0.", "141.101.",
		"162.158.", "172.64.", "172.65.", "172.66.", "172.67.", "173.245.",
		"188.114.", "190.93.", "197.234.", "198.41.",
	}
	
	for _, prefix := range cloudflareRanges {
		if strings.HasPrefix(ip, prefix) {
			return "Cloudflare"
		}
	}
	
	return ""
}

// uniqueStrings removes duplicates from string slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range input {
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// BruteSubdomains performs subdomain brute-force enumeration
func (s *DomainScanner) BruteSubdomains(ctx context.Context, domain string, wordlist []string) *DomainScanResult {
	result := &DomainScanResult{
		Domain:       domain,
		TotalChecked: len(wordlist),
		StartTime:    time.Now(),
		Subdomains:   make([]SubdomainResult, 0),
	}

	// 先检测泛解析
	s.detectWildcardDNS(ctx, domain)
	if len(s.WildcardIPs) > 0 {
		// 记录泛解析信息
		var wildcardIPList []string
		for ip := range s.WildcardIPs {
			wildcardIPList = append(wildcardIPList, ip)
		}
		fmt.Printf("[*] 检测到泛解析域名 %s, 泛解析IP: %v\n", domain, wildcardIPList)
	}

	// Get domain info first
	domainInfo := s.GetDomainInfo(ctx, domain)
	result.NSRecords = domainInfo.NSRecords
	result.MXRecords = domainInfo.MXRecords
	result.TXTRecords = domainInfo.TXTRecords

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.Concurrency)
	
	// 使用批量处理提高效率
	batchSize := 100
	for i := 0; i < len(wordlist); i += batchSize {
		select {
		case <-ctx.Done():
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime).String()
			return result
		default:
		}

		end := i + batchSize
		if end > len(wordlist) {
			end = len(wordlist)
		}
		batch := wordlist[i:end]

		for _, sub := range batch {
			wg.Add(1)
			semaphore <- struct{}{}

			go func(subdomain string) {
				defer wg.Done()
				defer func() { <-semaphore }()

				subResult := s.CheckSubdomain(ctx, subdomain, domain)
				if subResult.Alive {
					mu.Lock()
					result.Subdomains = append(result.Subdomains, *subResult)
					result.Found++
					mu.Unlock()
				}
			}(sub)
		}
	}

	wg.Wait()

	// Sort by subdomain name
	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Subdomain < result.Subdomains[j].Subdomain
	})

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// QuickSubdomainScan performs a quick subdomain scan with common subdomains
func (s *DomainScanner) QuickSubdomainScan(ctx context.Context, domain string) *DomainScanResult {
	wordlist := GetSubdomainWordlist()
	// Use first 200 for quick scan
	if len(wordlist) > 200 {
		wordlist = wordlist[:200]
	}
	return s.BruteSubdomains(ctx, domain, wordlist)
}

// FullSubdomainScan performs a full subdomain scan with extended wordlist
func (s *DomainScanner) FullSubdomainScan(ctx context.Context, domain string) *DomainScanResult {
	return s.BruteSubdomains(ctx, domain, GetSubdomainWordlist())
}

// CustomSubdomainScan performs subdomain scan with custom wordlist
func (s *DomainScanner) CustomSubdomainScan(ctx context.Context, domain string, wordlist []string) *DomainScanResult {
	return s.BruteSubdomains(ctx, domain, wordlist)
}

// ParseWordlist parses a wordlist string (newline or comma separated)
func ParseWordlist(input string) []string {
	var wordlist []string
	seen := make(map[string]bool)

	// Try newline separated first
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !seen[word] {
			seen[word] = true
			wordlist = append(wordlist, word)
		}
	}

	// If no newlines, try comma separated
	if len(wordlist) <= 1 && strings.Contains(input, ",") {
		wordlist = nil
		seen = make(map[string]bool)
		parts := strings.Split(input, ",")
		for _, part := range parts {
			word := strings.TrimSpace(part)
			if word != "" && !seen[word] {
				seen[word] = true
				wordlist = append(wordlist, word)
			}
		}
	}

	return wordlist
}
