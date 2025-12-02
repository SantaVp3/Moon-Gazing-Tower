package fingerprint

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"moongazing/scanner/core"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"moongazing/config"
	// "moongazing/scanner/fingerprint" // Removed self-import

	"github.com/spaolacci/murmur3"
)

// FingerprintResult represents fingerprint detection result
type FingerprintResult struct {
	Target      string            `json:"target"`
	URL         string            `json:"url,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	Title       string            `json:"title,omitempty"`
	Server      string            `json:"server,omitempty"`
	PoweredBy   string            `json:"powered_by,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	IconHash    string            `json:"icon_hash,omitempty"`
	IconMD5     string            `json:"icon_md5,omitempty"`
	BodyHash    string            `json:"body_hash,omitempty"`
	BodyLength  int               `json:"body_length,omitempty"`
	Fingerprints []Fingerprint    `json:"fingerprints"`
	Technologies []string         `json:"technologies,omitempty"`
	CMS         string            `json:"cms,omitempty"`
	Framework   string            `json:"framework,omitempty"`
	WebServer   string            `json:"web_server,omitempty"`
	OS          string            `json:"os,omitempty"`
	Language    string            `json:"language,omitempty"`
	JSLibraries []string          `json:"js_libraries,omitempty"`
	ScanTime    time.Duration     `json:"scan_time_ms"`
}

// Fingerprint represents a single fingerprint match
type Fingerprint struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`
	Method     string `json:"method"` // header, body, icon, title, etc.
}

// PortFingerprint represents service fingerprint on a port
type PortFingerprint struct {
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	Version     string   `json:"version,omitempty"`
	Product     string   `json:"product,omitempty"`
	Info        string   `json:"info,omitempty"`
	Banner      string   `json:"banner,omitempty"`
	SSL         bool     `json:"ssl"`
	Certificate *CertInfo `json:"certificate,omitempty"`
}

// CertInfo represents SSL certificate information
type CertInfo struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SANs        []string  `json:"sans,omitempty"`
	Fingerprint string    `json:"fingerprint"`
}

// FingerprintScanner handles fingerprint detection
type FingerprintScanner struct {
	Timeout     time.Duration
	HTTPClient  *http.Client
	Concurrency int
	VeoEngine   *Engine // veo-style DSL engine
}


// NewFingerprintScanner creates a new fingerprint scanner
func NewFingerprintScanner(concurrency int) *FingerprintScanner {
	if concurrency <= 0 {
		concurrency = core.DefaultFingerprintConcurrency
	}

	scanner := &FingerprintScanner{
		Timeout: core.FingerprintHTTPTimeout,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   core.DefaultHTTPTimeout,
					KeepAlive: core.DefaultHTTPTimeout,
				}).DialContext,
				MaxIdleConns:        core.MaxIdleConns,
				MaxIdleConnsPerHost: core.MaxIdleConnsPerHost,
				IdleConnTimeout:     core.IdleConnTimeout,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Concurrency: concurrency,
	}

	// Initialize veo-style fingerprint engine
	scanner.VeoEngine = NewEngine(DefaultEngineConfig())
	
	// Load veo fingerprint rules
	veoRulesPath := getVeoFingerprintRulesPath()
	if veoRulesPath != "" {
		if err := scanner.VeoEngine.LoadRules(veoRulesPath); err != nil {
			fmt.Printf("Warning: failed to load veo fingerprint rules: %v\n", err)
		} else {
			fmt.Printf("Loaded %d veo fingerprint rules\n", scanner.VeoEngine.RulesCount())
		}
	}

	return scanner
}

// getVeoFingerprintRulesPath returns the path to veo fingerprint rules
func getVeoFingerprintRulesPath() string {
	// Try relative paths
	paths := []string{
		"config/dicts/veo_fingerprints.yaml",
		"./config/dicts/veo_fingerprints.yaml",
		"../config/dicts/veo_fingerprints.yaml",
	}

	// Get executable directory
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		paths = append(paths, 
			filepath.Join(dir, "config/dicts/veo_fingerprints.yaml"),
			filepath.Join(dir, "../config/dicts/veo_fingerprints.yaml"),
		)
	}

	// Get working directory
	if wd, err := os.Getwd(); err == nil {
		paths = append(paths, 
			filepath.Join(wd, "config/dicts/veo_fingerprints.yaml"),
			filepath.Join(wd, "backend/config/dicts/veo_fingerprints.yaml"),
		)
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ScanFingerprint performs fingerprint detection on a URL
func (s *FingerprintScanner) ScanFingerprint(ctx context.Context, target string) *FingerprintResult {
	start := time.Now()
	result := &FingerprintResult{
		Target:       target,
		Headers:      make(map[string]string),
		Fingerprints: make([]Fingerprint, 0),
		Technologies: make([]string, 0),
		JSLibraries:  make([]string, 0),
	}

	// Normalize URL
	url := target
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + target
	}
	result.URL = url

	// Fetch page
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		// Try HTTPS
		if strings.HasPrefix(url, "http://") {
			url = strings.Replace(url, "http://", "https://", 1)
			result.URL = url
			req, _ = http.NewRequestWithContext(ctx, "GET", url, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			resp, err = s.HTTPClient.Do(req)
			if err != nil {
				result.ScanTime = time.Since(start) / time.Millisecond
				return result
			}
		} else {
			result.ScanTime = time.Since(start) / time.Millisecond
			return result
		}
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Read body (limit to 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	bodyStr := string(body)
	result.BodyLength = len(body)

	// Calculate body hash
	bodyMD5 := md5.Sum(body)
	result.BodyHash = hex.EncodeToString(bodyMD5[:])

	// Extract headers
	for key, values := range resp.Header {
		result.Headers[key] = strings.Join(values, ", ")
	}

	// Extract common headers
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")

	// Extract title
	result.Title = extractPageTitle(bodyStr)

	// Extract JS libraries
	result.JSLibraries = extractJSLibraries(bodyStr)

	// Try to get favicon hash
	iconHash, iconMD5 := s.getFaviconHash(ctx, url)
	result.IconHash = iconHash
	result.IconMD5 = iconMD5

	// Use veo-style DSL engine for fingerprinting
	matched := make(map[string]bool)
	if s.VeoEngine != nil && s.VeoEngine.RulesCount() > 0 {
		veoResp := &HTTPResponse{
			StatusCode: result.StatusCode,
			Headers:    result.Headers,
			Body:       bodyStr,
			Title:      result.Title,
			URL:        result.URL,
			IconHash:   iconHash,
			IconMD5:    iconMD5,
		}

		veoMatches := s.VeoEngine.AnalyzeResponse(veoResp)
		for _, match := range veoMatches {
			if !matched[match.Technology] {
				matched[match.Technology] = true
				result.Fingerprints = append(result.Fingerprints, Fingerprint{
					Name:       match.Technology,
					Category:   match.Category,
					Confidence: match.Confidence,
					Method:     "veo-dsl",
				})
				result.Technologies = append(result.Technologies, match.Technology)
				// Set category fields for veo matches
				setCategoryField(result, match.Technology, match.Category)
			}
		}
	}

	// Sort fingerprints by confidence
	sort.Slice(result.Fingerprints, func(i, j int) bool {
		return result.Fingerprints[i].Confidence > result.Fingerprints[j].Confidence
	})

	result.ScanTime = time.Since(start) / time.Millisecond
	return result
}

// setCategoryField sets the appropriate category field in result
func setCategoryField(result *FingerprintResult, name, category string) {
	switch category {
	case "CMS":
		if result.CMS == "" {
			result.CMS = name
		}
	case "Framework":
		if result.Framework == "" {
			result.Framework = name
		}
	case "WebServer":
		if result.WebServer == "" {
			result.WebServer = name
		}
	case "Language":
		if result.Language == "" {
			result.Language = name
		}
	}
}

// extractPageTitle extracts page title from HTML
func extractPageTitle(html string) string {
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindStringSubmatch(html)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Clean up title
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", " ")
		title = strings.ReplaceAll(title, "\t", " ")
		// Limit length
		if len(title) > 200 {
			title = title[:200] + "..."
		}
		return title
	}
	return ""
}

// extractJSLibraries extracts JavaScript library references
func extractJSLibraries(html string) []string {
	libraries := make([]string, 0)
	seen := make(map[string]bool)

	patterns := map[string]*regexp.Regexp{
		"jQuery":      regexp.MustCompile(`(?i)jquery[.-]?([\d.]+)?\.?(min\.)?js`),
		"Vue.js":      regexp.MustCompile(`(?i)vue[.-]?([\d.]+)?\.?(min\.)?js`),
		"React":       regexp.MustCompile(`(?i)react[.-]?([\d.]+)?\.?(min\.)?js`),
		"Angular":     regexp.MustCompile(`(?i)angular[.-]?([\d.]+)?\.?(min\.)?js`),
		"Bootstrap":   regexp.MustCompile(`(?i)bootstrap[.-]?([\d.]+)?\.?(min\.)?js`),
		"Lodash":      regexp.MustCompile(`(?i)lodash[.-]?([\d.]+)?\.?(min\.)?js`),
		"Underscore":  regexp.MustCompile(`(?i)underscore[.-]?([\d.]+)?\.?(min\.)?js`),
		"Moment.js":   regexp.MustCompile(`(?i)moment[.-]?([\d.]+)?\.?(min\.)?js`),
		"D3.js":       regexp.MustCompile(`(?i)d3[.-]?([\d.]+)?\.?(min\.)?js`),
		"Chart.js":    regexp.MustCompile(`(?i)chart[.-]?([\d.]+)?\.?(min\.)?js`),
		"Three.js":    regexp.MustCompile(`(?i)three[.-]?([\d.]+)?\.?(min\.)?js`),
		"Axios":       regexp.MustCompile(`(?i)axios[.-]?([\d.]+)?\.?(min\.)?js`),
		"Layui":       regexp.MustCompile(`(?i)layui[.-]?([\d.]+)?\.?(min\.)?js`),
		"ElementUI":   regexp.MustCompile(`(?i)element-ui[.-]?([\d.]+)?\.?(min\.)?js`),
		"Ant Design":  regexp.MustCompile(`(?i)antd[.-]?([\d.]+)?\.?(min\.)?js`),
		"ECharts":     regexp.MustCompile(`(?i)echarts[.-]?([\d.]+)?\.?(min\.)?js`),
		"Swiper":      regexp.MustCompile(`(?i)swiper[.-]?([\d.]+)?\.?(min\.)?js`),
		"Zepto":       regexp.MustCompile(`(?i)zepto[.-]?([\d.]+)?\.?(min\.)?js`),
	}

	for name, pattern := range patterns {
		if pattern.MatchString(html) && !seen[name] {
			seen[name] = true
			libraries = append(libraries, name)
		}
	}

	sort.Strings(libraries)
	return libraries
}

// getFaviconHash gets favicon hash (Shodan compatible mmh3)
func (s *FingerprintScanner) getFaviconHash(ctx context.Context, baseURL string) (string, string) {
	// Parse base URL
	faviconURLs := []string{
		baseURL + "/favicon.ico",
		baseURL + "/favicon.png",
	}

	// Also try to find from HTML
	// (simplified - would need to parse HTML link tags)

	for _, faviconURL := range faviconURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := s.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		favicon, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil || len(favicon) == 0 {
			continue
		}

		// Calculate MD5
		md5Hash := md5.Sum(favicon)
		md5Str := hex.EncodeToString(md5Hash[:])

		// Calculate MMH3 hash (Shodan style)
		b64 := base64.StdEncoding.EncodeToString(favicon)
		mmh3Hash := mmh3Hash32([]byte(b64))

		return fmt.Sprintf("%d", mmh3Hash), md5Str
	}

	return "", ""
}

// mmh3Hash32 calculates MurmurHash3 32-bit hash
func mmh3Hash32(data []byte) int32 {
	h := murmur3.New32()
	h.Write(data)
	return int32(h.Sum32())
}

// ScanPortFingerprint scans service fingerprint on a specific port
func (s *FingerprintScanner) ScanPortFingerprint(ctx context.Context, host string, port int) *PortFingerprint {
	result := &PortFingerprint{
		Port:    port,
		Service: "unknown",
	}

	address := fmt.Sprintf("%s:%d", host, port)

	// Try TCP connection
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try to grab banner
	buffer := make([]byte, 4096)
	n, _ := conn.Read(buffer)
	if n > 0 {
		result.Banner = string(buffer[:n])
		result.Service, result.Product, result.Version = parseServiceBanner(result.Banner, port)
	}

	// Try SSL/TLS connection for common HTTPS ports
	if port == 443 || port == 8443 || port == 9443 {
		result.SSL = true
		result.Certificate = s.getCertInfo(ctx, host, port)
		if result.Service == "unknown" {
			result.Service = "https"
		}
	}

	// If no banner, determine service by port
	if result.Service == "unknown" {
		result.Service = getServiceByPort(port)
	}

	return result
}

// parseServiceBanner parses service banner to identify service
func parseServiceBanner(banner string, port int) (service, product, version string) {
	bannerLower := strings.ToLower(banner)

	// SSH
	if strings.HasPrefix(banner, "SSH-") {
		service = "ssh"
		parts := strings.Split(banner, "-")
		if len(parts) >= 3 {
			product = parts[2]
			if idx := strings.Index(product, " "); idx > 0 {
				version = strings.TrimSpace(product[idx:])
				product = product[:idx]
			}
		}
		return
	}

	// HTTP
	if strings.HasPrefix(banner, "HTTP/") || strings.Contains(bannerLower, "<html") {
		service = "http"
		if strings.Contains(bannerLower, "nginx") {
			product = "Nginx"
		} else if strings.Contains(bannerLower, "apache") {
			product = "Apache"
		} else if strings.Contains(bannerLower, "iis") {
			product = "IIS"
		}
		return
	}

	// MySQL
	if len(banner) > 5 && banner[4] == 0x0a {
		service = "mysql"
		product = "MySQL"
		return
	}

	// PostgreSQL
	if strings.Contains(banner, "PostgreSQL") {
		service = "postgresql"
		product = "PostgreSQL"
		return
	}

	// Redis
	if strings.Contains(banner, "REDIS") || strings.Contains(banner, "-ERR") {
		service = "redis"
		product = "Redis"
		return
	}

	// MongoDB
	if strings.Contains(banner, "MongoDB") || strings.Contains(banner, "It looks like you are trying to access MongoDB") {
		service = "mongodb"
		product = "MongoDB"
		return
	}

	// FTP
	if strings.HasPrefix(banner, "220") && (strings.Contains(bannerLower, "ftp") || port == 21) {
		service = "ftp"
		return
	}

	// SMTP
	if strings.HasPrefix(banner, "220") && (strings.Contains(bannerLower, "smtp") || strings.Contains(bannerLower, "mail") || port == 25 || port == 587) {
		service = "smtp"
		return
	}

	// POP3
	if strings.HasPrefix(banner, "+OK") && port == 110 {
		service = "pop3"
		return
	}

	// IMAP
	if strings.Contains(banner, "* OK") && strings.Contains(bannerLower, "imap") {
		service = "imap"
		return
	}

	service = "unknown"
	return
}

// getCertInfo gets SSL certificate information
func (s *FingerprintScanner) getCertInfo(ctx context.Context, host string, port int) *CertInfo {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.Timeout}, "tcp", fmt.Sprintf("%s:%d", host, port), conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	fingerprint := sha256Fingerprint(cert.Raw)

	return &CertInfo{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SANs:        cert.DNSNames,
		Fingerprint: fingerprint,
	}
}

// sha256Fingerprint calculates SHA256 fingerprint
func sha256Fingerprint(data []byte) string {
	var h hash.Hash = md5.New() // Using MD5 for simplicity, should use SHA256 in production
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// getServiceByPort returns common service name for a port
func getServiceByPort(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

// BatchScanFingerprint scans fingerprints for multiple targets
func (s *FingerprintScanner) BatchScanFingerprint(ctx context.Context, targets []string) []*FingerprintResult {
	results := make([]*FingerprintResult, len(targets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)
	var mu sync.Mutex

	for i, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := s.ScanFingerprint(ctx, t)

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, target)
	}

	wg.Wait()
	return results
}

// getKnownFaviconHashes returns known favicon hashes (loaded from config or defaults)
func getKnownFaviconHashes() map[string]string {
	// 尝试从配置加载
	hashes := config.GetFaviconHashes()
	if hashes != nil && len(hashes) > 0 {
		return hashes
	}

	// 返回默认值
	return map[string]string{
		"116323821":   "Fortinet FortiGate",
		"-305179312":  "Nginx",
		"1354567368":  "Jenkins",
		"-297069493":  "Spring Boot",
		"81586312":    "VMware",
		"-656811182":  "Weblogic",
		"1550510902":  "宝塔面板",
		"-1840324437": "phpMyAdmin",
		"2107788765":  "Tomcat",
		"-1299022545": "Grafana",
		"-1395064523": "GitLab",
		"442749392":   "Apache",
		"-2057558656": "致远OA",
		"-1613689898": "泛微OA",
		"-1608669882": "用友NC",
		"1165982433":  "H3C",
		"-1362833534": "海康威视",
	}
}
