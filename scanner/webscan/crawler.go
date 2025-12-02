package webscan

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"moongazing/scanner/core"
)

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
	URL     string      `json:"url"`
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	Inputs  []FormInput `json:"inputs"`
	HasFile bool        `json:"has_file"`
}

// FormInput represents form input field
type FormInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// CrawlExtras holds extra information found during crawling
type CrawlExtras struct {
	Emails   []string
	JSFiles  []string
	Comments []string
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
		concurrency = core.DefaultCrawlerConcurrency
	}

	return &WebCrawler{
		MaxDepth:    maxDepth,
		MaxURLs:     maxURLs,
		Concurrency: concurrency,
		Timeout:     core.DefaultHTTPTimeout,
		HTTPClient: &http.Client{
			Timeout: core.DefaultHTTPTimeout,
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
	targetRoot := core.ExtractRootDomain(targetHost)
	baseRoot := core.ExtractRootDomain(baseDomain)

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
