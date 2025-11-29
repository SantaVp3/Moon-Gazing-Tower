package scanner

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"moongazing/config"
)

// DirScanResult represents directory scan result
type DirScanResult struct {
	Target       string       `json:"target"`
	TotalChecked int          `json:"total_checked"`
	Found        int          `json:"found"`
	StartTime    time.Time    `json:"start_time"`
	EndTime      time.Time    `json:"end_time"`
	Duration     string       `json:"duration"`
	Results      []DirEntry   `json:"results"`
}

// DirEntry represents a discovered directory or file
type DirEntry struct {
	URL          string `json:"url"`
	Path         string `json:"path"`
	StatusCode   int    `json:"status_code"`
	ContentType  string `json:"content_type,omitempty"`
	ContentLength int64  `json:"content_length"`
	Title        string `json:"title,omitempty"`
	RedirectTo   string `json:"redirect_to,omitempty"`
}

// SensitiveResult represents sensitive information detection result
type SensitiveResult struct {
	Target    string             `json:"target"`
	URL       string             `json:"url"`
	Found     int                `json:"found"`
	Findings  []SensitiveFinding `json:"findings"`
	ScanTime  time.Duration      `json:"scan_time_ms"`
}

// SensitiveFinding represents a single sensitive information finding
type SensitiveFinding struct {
	Type       string   `json:"type"`
	Pattern    string   `json:"pattern"`
	Matches    []string `json:"matches"`
	Location   string   `json:"location"` // url, body, header, js
	Severity   string   `json:"severity"`
	Confidence int      `json:"confidence"`
}

// CrawlerResult represents web crawler result
type CrawlerResult struct {
	Target     string       `json:"target"`
	TotalURLs  int          `json:"total_urls"`
	TotalForms int          `json:"total_forms"`
	StartTime  time.Time    `json:"start_time"`
	EndTime    time.Time    `json:"end_time"`
	Duration   string       `json:"duration"`
	URLs       []CrawledURL `json:"urls"`
	Forms      []FormInfo   `json:"forms"`
	Emails     []string     `json:"emails,omitempty"`
	JSFiles    []string     `json:"js_files,omitempty"`
	Comments   []string     `json:"comments,omitempty"`
}

// CrawledURL represents a crawled URL
type CrawledURL struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code,omitempty"`
	Source     string `json:"source"` // link, form, js, redirect
	Depth      int    `json:"depth"`
}

// FormInfo represents form information
type FormInfo struct {
	URL      string      `json:"url"`
	Action   string      `json:"action"`
	Method   string      `json:"method"`
	Inputs   []FormInput `json:"inputs"`
	HasFile  bool        `json:"has_file"`
}

// FormInput represents form input field
type FormInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// ContentScanner handles content scanning (directory brute, sensitive info, crawler)
type ContentScanner struct {
	Timeout        time.Duration
	HTTPClient     *http.Client
	Concurrency    int
	UserAgent      string
	Wordlist       []string
	Extensions     []string
	FollowRedirect bool           // 是否跟随重定向
	MaxRedirects   int            // 最大重定向次数
	Filter         *ResponseFilter // 响应去重过滤器
}

// NewContentScanner creates a new content scanner
func NewContentScanner(concurrency int) *ContentScanner {
	if concurrency <= 0 {
		concurrency = 20
	}

	return &ContentScanner{
		Timeout: 10 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 5 * time.Second,
				}).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 手动处理重定向
			},
		},
		Concurrency:    concurrency,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Wordlist:       getWordlistFromConfig(),
		Extensions:     getExtensionsFromConfig(),
		FollowRedirect: true, // 默认跟随重定向
		MaxRedirects:   5,    // 最大5次重定向
		Filter:         NewResponseFilter(DefaultFilterConfig()),
	}
}

// getWordlistFromConfig loads directory wordlist from configuration
func getWordlistFromConfig() []string {
	wordlist := config.GetDirectories()
	if len(wordlist) > 0 {
		return wordlist
	}
	// Fallback to minimal defaults
	return []string{"admin", "api", "login", "backup", "config", ".git", ".env"}
}

// getExtensionsFromConfig loads backup extensions from configuration
func getExtensionsFromConfig() []string {
	exts := config.GetBackupExtensions()
	// Always include empty extension for directory scanning
	result := []string{""}
	if len(exts) > 0 {
		result = append(result, exts...)
	} else {
		result = append(result, ".php", ".asp", ".aspx", ".jsp", ".html", ".bak", ".old", ".zip", ".sql")
	}
	return result
}

// DirBrute performs directory brute force scanning
func (s *ContentScanner) DirBrute(ctx context.Context, target string, wordlist []string, extensions []string) *DirScanResult {
	result := &DirScanResult{
		Target:    target,
		StartTime: time.Now(),
		Results:   make([]DirEntry, 0),
	}

	if wordlist == nil {
		wordlist = s.Wordlist
	}
	if extensions == nil {
		extensions = s.Extensions
	}

	// Normalize target URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	target = strings.TrimSuffix(target, "/")

	// Build paths to check
	var paths []string
	for _, word := range wordlist {
		for _, ext := range extensions {
			paths = append(paths, "/"+word+ext)
		}
	}

	// 重置过滤器状态（每次扫描开始前）
	if s.Filter != nil {
		s.Filter.Reset()
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.Concurrency)

	for _, path := range paths {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			entry := s.checkPathWithRedirect(ctx, target, p)
			if entry != nil {
				// 应用去重过滤
				if s.Filter != nil && s.Filter.ShouldFilter(entry) {
					// 页面被判定为重复/无效，跳过
					mu.Lock()
					result.TotalChecked++
					mu.Unlock()
					return
				}
				
				mu.Lock()
				result.Results = append(result.Results, *entry)
				result.Found++
				result.TotalChecked++
				mu.Unlock()
			} else {
				mu.Lock()
				result.TotalChecked++
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()

	// Sort results by status code
	sort.Slice(result.Results, func(i, j int) bool {
		return result.Results[i].StatusCode < result.Results[j].StatusCode
	})

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// checkPathWithRedirect checks if a path exists and follows redirects to final page
func (s *ContentScanner) checkPathWithRedirect(ctx context.Context, baseURL, path string) *DirEntry {
	currentURL := baseURL + path
	originalURL := currentURL

	// 跟随重定向（最多 MaxRedirects 次）
	for redirectCount := 0; redirectCount <= s.MaxRedirects; redirectCount++ {
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", s.UserAgent)

		resp, err := s.HTTPClient.Do(req)
		if err != nil {
			return nil
		}

		// 读取响应体
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768)) // 32KB 足够检测重定向
		resp.Body.Close()

		// 检查是否为服务器端重定向 (3xx)
		if s.FollowRedirect && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location != "" {
				// 解析重定向 URL
				nextURL := ResolveRedirectURL(currentURL, location)
				if nextURL != "" && ShouldFollowRedirect(currentURL, nextURL) {
					currentURL = nextURL
					continue
				}
			}
		}

		// 检查是否为客户端重定向 (meta refresh / JS)
		if s.FollowRedirect && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			redirectURL := DetectClientRedirectURL(string(body))
			if redirectURL != "" {
				nextURL := ResolveRedirectURL(currentURL, redirectURL)
				if nextURL != "" && ShouldFollowRedirect(currentURL, nextURL) {
					currentURL = nextURL
					continue
				}
			}
		}

		// 已到达最终页面，进行判断
		// 过滤常见的无效状态码
		if resp.StatusCode == 404 || resp.StatusCode == 400 {
			return nil
		}

		entry := &DirEntry{
			URL:           originalURL, // 保留原始扫描 URL
			Path:          path,
			StatusCode:    resp.StatusCode,
			ContentType:   resp.Header.Get("Content-Type"),
			ContentLength: int64(len(body)),
		}

		// 如果发生了重定向，记录最终 URL
		if currentURL != originalURL {
			entry.RedirectTo = currentURL
		}

		// 提取标题（用于去重判断）
		if strings.Contains(entry.ContentType, "text/html") {
			entry.Title = extractTitle(string(body))
		}

		return entry
	}

	return nil
}

// checkPath checks if a path exists (original method, kept for compatibility)
func (s *ContentScanner) checkPath(ctx context.Context, baseURL, path string) *DirEntry {
	url := baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Filter common non-interesting status codes
	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 500 {
		return nil
	}

	entry := &DirEntry{
		URL:           url,
		Path:          path,
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
	}

	// Handle redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		entry.RedirectTo = resp.Header.Get("Location")
	}

	// Try to get title for HTML pages
	if strings.Contains(entry.ContentType, "text/html") && resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
		entry.Title = extractTitle(string(body))
	}

	return entry
}

// QuickDirScan performs a quick directory scan with common paths
func (s *ContentScanner) QuickDirScan(ctx context.Context, target string) *DirScanResult {
	quickList := s.Wordlist
	if len(quickList) > 50 {
		quickList = quickList[:50]
	}
	return s.DirBrute(ctx, target, quickList, []string{""})
}

// SensitivePattern represents a sensitive information pattern
type SensitivePattern struct {
	Name     string
	Pattern  string
	Type     string
	Severity string
	Regex    *regexp.Regexp
}

// loadSensitivePatternsFromConfig loads sensitive patterns from configuration
func loadSensitivePatternsFromConfig() map[string]*SensitivePattern {
	patterns := make(map[string]*SensitivePattern)
	vulnConfig := config.GetVulnConfig()
	
	if vulnConfig != nil && len(vulnConfig.SensitivePatterns) > 0 {
		for _, p := range vulnConfig.SensitivePatterns {
			regex, err := regexp.Compile(p.Pattern)
			if err != nil {
				continue
			}
			patterns[p.Name] = &SensitivePattern{
				Name:     p.Name,
				Pattern:  p.Pattern,
				Type:     "sensitive",
				Severity: p.Severity,
				Regex:    regex,
			}
		}
	}
	
	// Add minimal defaults if no config
	if len(patterns) == 0 {
		patterns = getDefaultSensitivePatterns()
	}
	
	return patterns
}

// getDefaultSensitivePatterns returns minimal default patterns
func getDefaultSensitivePatterns() map[string]*SensitivePattern {
	patterns := map[string]*SensitivePattern{
		"password_field": {
			Name:     "password_field",
			Pattern:  `(?i)(password|passwd|pwd|secret)\s*[=:]\s*['"]([^'"]+)['"]`,
			Type:     "credential",
			Severity: "high",
		},
		"api_key": {
			Name:     "api_key",
			Pattern:  `(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]([a-zA-Z0-9_-]{16,})['"]`,
			Type:     "credential",
			Severity: "high",
		},
		"private_key": {
			Name:     "private_key",
			Pattern:  `-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`,
			Type:     "credential",
			Severity: "critical",
		},
		"email": {
			Name:     "email",
			Pattern:  `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Type:     "pii",
			Severity: "low",
		},
	}
	
	// Compile regex
	for _, p := range patterns {
		p.Regex = regexp.MustCompile(p.Pattern)
	}
	
	return patterns
}

// Global sensitive patterns (loaded once)
var sensitivePatterns map[string]*SensitivePattern
var sensitivePatternOnce sync.Once

// getSensitivePatterns returns the sensitive patterns, loading if needed
func getSensitivePatterns() map[string]*SensitivePattern {
	sensitivePatternOnce.Do(func() {
		sensitivePatterns = loadSensitivePatternsFromConfig()
	})
	return sensitivePatterns
}

// ScanSensitiveInfo scans for sensitive information in a URL
func (s *ContentScanner) ScanSensitiveInfo(ctx context.Context, target string) *SensitiveResult {
	start := time.Now()
	result := &SensitiveResult{
		Target:   target,
		Findings: make([]SensitiveFinding, 0),
	}

	// Normalize URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	result.URL = target

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		result.ScanTime = time.Since(start) / time.Millisecond
		return result
	}
	bodyStr := string(body)

	// Get sensitive patterns from config
	patterns := getSensitivePatterns()

	// Check body for sensitive patterns
	for name, pattern := range patterns {
		matches := pattern.Regex.FindAllString(bodyStr, 10) // Limit to 10 matches
		if len(matches) > 0 {
			// Deduplicate
			seen := make(map[string]bool)
			uniqueMatches := make([]string, 0)
			for _, m := range matches {
				if !seen[m] && len(m) < 200 { // Skip very long matches
					seen[m] = true
					uniqueMatches = append(uniqueMatches, m)
				}
			}

			if len(uniqueMatches) > 0 {
				result.Findings = append(result.Findings, SensitiveFinding{
					Type:       pattern.Type,
					Pattern:    name,
					Matches:    uniqueMatches,
					Location:   "body",
					Severity:   pattern.Severity,
					Confidence: 70,
				})
				result.Found += len(uniqueMatches)
			}
		}
	}

	// Check headers for sensitive info
	headerStr := ""
	for k, v := range resp.Header {
		headerStr += k + ": " + strings.Join(v, ", ") + "\n"
	}

	// Check for server version disclosure in headers
	if serverHeader := resp.Header.Get("Server"); serverHeader != "" {
		if strings.Contains(serverHeader, "/") {
			result.Findings = append(result.Findings, SensitiveFinding{
				Type:       "info",
				Pattern:    "server_version",
				Matches:    []string{serverHeader},
				Location:   "header",
				Severity:   "info",
				Confidence: 90,
			})
			result.Found++
		}
	}

	// Check X-Powered-By
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		result.Findings = append(result.Findings, SensitiveFinding{
			Type:       "info",
			Pattern:    "powered_by",
			Matches:    []string{poweredBy},
			Location:   "header",
			Severity:   "info",
			Confidence: 90,
		})
		result.Found++
	}

	// Sort by severity
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(result.Findings, func(i, j int) bool {
		return severityOrder[result.Findings[i].Severity] < severityOrder[result.Findings[j].Severity]
	})

	result.ScanTime = time.Since(start) / time.Millisecond
	return result
}

// WebCrawler crawls a website
type WebCrawler struct {
	MaxDepth    int
	MaxURLs     int
	Concurrency int
	Timeout     time.Duration
	HTTPClient  *http.Client
	UserAgent   string
	SameDomain  bool
}

// NewWebCrawler creates a new web crawler
func NewWebCrawler(maxDepth, maxURLs, concurrency int) *WebCrawler {
	if maxDepth <= 0 {
		maxDepth = 3
	}
	if maxURLs <= 0 {
		maxURLs = 100
	}
	if concurrency <= 0 {
		concurrency = 10
	}

	return &WebCrawler{
		MaxDepth:    maxDepth,
		MaxURLs:     maxURLs,
		Concurrency: concurrency,
		Timeout:     10 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		UserAgent:  "Mozilla/5.0 (compatible; WebCrawler/1.0)",
		SameDomain: true,
	}
}

// Crawl crawls a website starting from the given URL
func (c *WebCrawler) Crawl(ctx context.Context, startURL string) *CrawlerResult {
	result := &CrawlerResult{
		Target:    startURL,
		StartTime: time.Now(),
		URLs:      make([]CrawledURL, 0),
		Forms:     make([]FormInfo, 0),
		Emails:    make([]string, 0),
		JSFiles:   make([]string, 0),
		Comments:  make([]string, 0),
	}

	// Normalize URL
	if !strings.HasPrefix(startURL, "http://") && !strings.HasPrefix(startURL, "https://") {
		startURL = "http://" + startURL
	}

	parsedStart, err := url.Parse(startURL)
	if err != nil {
		return result
	}
	baseDomain := parsedStart.Host

	visited := make(map[string]bool)
	var mu sync.Mutex
	queue := make(chan CrawledURL, c.MaxURLs*2)
	var wg sync.WaitGroup

	// Add initial URL
	queue <- CrawledURL{URL: startURL, Depth: 0, Source: "start"}

	// Worker goroutines
	for i := 0; i < c.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case crawled, ok := <-queue:
					if !ok {
						return
					}

					mu.Lock()
					if visited[crawled.URL] || len(result.URLs) >= c.MaxURLs {
						mu.Unlock()
						continue
					}
					visited[crawled.URL] = true
					result.URLs = append(result.URLs, crawled)
					mu.Unlock()

					if crawled.Depth >= c.MaxDepth {
						continue
					}

					// Fetch and parse page
					links, forms, extras := c.fetchAndParse(ctx, crawled.URL, baseDomain)

					// Add new links to queue
					for _, link := range links {
						mu.Lock()
						if !visited[link] && len(result.URLs) < c.MaxURLs {
							select {
							case queue <- CrawledURL{URL: link, Depth: crawled.Depth + 1, Source: "link"}:
							default:
							}
						}
						mu.Unlock()
					}

					// Add forms
					mu.Lock()
					result.Forms = append(result.Forms, forms...)
					result.Emails = appendUnique(result.Emails, extras.Emails)
					result.JSFiles = appendUnique(result.JSFiles, extras.JSFiles)
					result.Comments = appendUnique(result.Comments, extras.Comments)
					mu.Unlock()
				}
			}
		}()
	}

	// Wait for crawling to complete with timeout
	done := make(chan struct{})
	go func() {
		time.Sleep(time.Duration(c.MaxURLs) * 100 * time.Millisecond) // Rough timeout
		close(queue)
		close(done)
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}

	wg.Wait()

	result.TotalURLs = len(result.URLs)
	result.TotalForms = len(result.Forms)
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// CrawlExtras holds extra information found during crawling
type CrawlExtras struct {
	Emails   []string
	JSFiles  []string
	Comments []string
}

// fetchAndParse fetches a URL and parses it for links and forms
func (c *WebCrawler) fetchAndParse(ctx context.Context, targetURL, baseDomain string) ([]string, []FormInfo, CrawlExtras) {
	var links []string
	var forms []FormInfo
	var extras CrawlExtras

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return links, forms, extras
	}
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return links, forms, extras
	}
	defer resp.Body.Close()

	// Only parse HTML pages
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return links, forms, extras
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return links, forms, extras
	}
	bodyStr := string(body)

	parsedBase, _ := url.Parse(targetURL)

	// Extract links
	linkRegex := regexp.MustCompile(`(?i)href\s*=\s*['"]([^'"]+)['"]`)
	linkMatches := linkRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range linkMatches {
		if len(match) > 1 {
			link := resolveURL(parsedBase, match[1])
			if link != "" && (!c.SameDomain || isSameDomain(link, baseDomain)) {
				links = append(links, link)
			}
		}
	}

	// Extract JS files
	jsRegex := regexp.MustCompile(`(?i)src\s*=\s*['"]([^'"]*\.js[^'"]*?)['"]`)
	jsMatches := jsRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range jsMatches {
		if len(match) > 1 {
			jsURL := resolveURL(parsedBase, match[1])
			if jsURL != "" {
				extras.JSFiles = append(extras.JSFiles, jsURL)
			}
		}
	}

	// Extract forms
	formRegex := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range formMatches {
		if len(match) > 1 {
			form := parseForm(match[0], parsedBase, targetURL)
			if form.Action != "" {
				forms = append(forms, form)
			}
		}
	}

	// Extract emails
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emailMatches := emailRegex.FindAllString(bodyStr, 50)
	extras.Emails = emailMatches

	// Extract HTML comments
	commentRegex := regexp.MustCompile(`<!--([\s\S]*?)-->`)
	commentMatches := commentRegex.FindAllStringSubmatch(bodyStr, 20)
	for _, match := range commentMatches {
		if len(match) > 1 {
			comment := strings.TrimSpace(match[1])
			if len(comment) > 10 && len(comment) < 500 { // Filter out trivial comments
				extras.Comments = append(extras.Comments, comment)
			}
		}
	}

	return links, forms, extras
}

// parseForm parses a form HTML
func parseForm(formHTML string, baseURL *url.URL, pageURL string) FormInfo {
	form := FormInfo{
		URL:    pageURL,
		Method: "GET",
		Inputs: make([]FormInput, 0),
	}

	// Get action
	actionRegex := regexp.MustCompile(`(?i)action\s*=\s*['"]([^'"]*?)['"]`)
	if match := actionRegex.FindStringSubmatch(formHTML); len(match) > 1 {
		form.Action = resolveURL(baseURL, match[1])
	} else {
		form.Action = pageURL
	}

	// Get method
	methodRegex := regexp.MustCompile(`(?i)method\s*=\s*['"]([^'"]*?)['"]`)
	if match := methodRegex.FindStringSubmatch(formHTML); len(match) > 1 {
		form.Method = strings.ToUpper(match[1])
	}

	// Get inputs
	inputRegex := regexp.MustCompile(`(?i)<input[^>]*>`)
	inputMatches := inputRegex.FindAllString(formHTML, -1)
	for _, input := range inputMatches {
		fi := FormInput{}

		nameRegex := regexp.MustCompile(`(?i)name\s*=\s*['"]([^'"]*?)['"]`)
		if match := nameRegex.FindStringSubmatch(input); len(match) > 1 {
			fi.Name = match[1]
		}

		typeRegex := regexp.MustCompile(`(?i)type\s*=\s*['"]([^'"]*?)['"]`)
		if match := typeRegex.FindStringSubmatch(input); len(match) > 1 {
			fi.Type = match[1]
		} else {
			fi.Type = "text"
		}

		valueRegex := regexp.MustCompile(`(?i)value\s*=\s*['"]([^'"]*?)['"]`)
		if match := valueRegex.FindStringSubmatch(input); len(match) > 1 {
			fi.Value = match[1]
		}

		if fi.Name != "" {
			form.Inputs = append(form.Inputs, fi)
		}

		if fi.Type == "file" {
			form.HasFile = true
		}
	}

	// Get textareas
	textareaRegex := regexp.MustCompile(`(?i)<textarea[^>]*name\s*=\s*['"]([^'"]*?)['"][^>]*>`)
	textareaMatches := textareaRegex.FindAllStringSubmatch(formHTML, -1)
	for _, match := range textareaMatches {
		if len(match) > 1 {
			form.Inputs = append(form.Inputs, FormInput{
				Name: match[1],
				Type: "textarea",
			})
		}
	}

	// Get selects
	selectRegex := regexp.MustCompile(`(?i)<select[^>]*name\s*=\s*['"]([^'"]*?)['"][^>]*>`)
	selectMatches := selectRegex.FindAllStringSubmatch(formHTML, -1)
	for _, match := range selectMatches {
		if len(match) > 1 {
			form.Inputs = append(form.Inputs, FormInput{
				Name: match[1],
				Type: "select",
			})
		}
	}

	return form
}

// resolveURL resolves a relative URL against a base URL
func resolveURL(base *url.URL, href string) string {
	// Skip javascript, mailto, tel links
	if strings.HasPrefix(strings.ToLower(href), "javascript:") ||
		strings.HasPrefix(strings.ToLower(href), "mailto:") ||
		strings.HasPrefix(strings.ToLower(href), "tel:") ||
		strings.HasPrefix(href, "#") ||
		href == "" {
		return ""
	}

	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)
	// Clean fragment
	resolved.Fragment = ""

	return resolved.String()
}

// isSameDomain checks if URL belongs to the same domain
// Correctly handles second-level TLDs like .com.cn, .co.uk, etc.
func isSameDomain(targetURL, baseDomain string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	targetHost := parsed.Host
	
	// Direct match
	if targetHost == baseDomain {
		return true
	}
	
	// Check if subdomain of baseDomain
	if strings.HasSuffix(targetHost, "."+baseDomain) {
		return true
	}
	
	// Extract root domains and compare
	targetRoot := ExtractRootDomain(targetHost)
	baseRoot := ExtractRootDomain(baseDomain)
	
	return targetRoot == baseRoot
}

// appendUnique appends unique items to a slice
func appendUnique(slice []string, items []string) []string {
	seen := make(map[string]bool)
	for _, s := range slice {
		seen[s] = true
	}

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			slice = append(slice, item)
		}
	}

	return slice
}

// BatchScanSensitive scans multiple URLs for sensitive information
func (s *ContentScanner) BatchScanSensitive(ctx context.Context, targets []string) []*SensitiveResult {
	results := make([]*SensitiveResult, len(targets))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Concurrency)
	var mu sync.Mutex

	for i, target := range targets {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(idx int, t string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := s.ScanSensitiveInfo(ctx, t)

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, target)
	}

	wg.Wait()
	return results
}
