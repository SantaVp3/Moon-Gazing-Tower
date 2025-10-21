package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// Crawler 爬虫
type Crawler struct {
	client      *http.Client
	visited     map[string]bool
	visitedLock sync.Mutex
	maxDepth    int
	maxPages    int
	timeout     time.Duration
	userAgent   string
}

// CrawlerConfig 爬虫配置
type CrawlerConfig struct {
	MaxDepth int
	MaxPages int
	Timeout  time.Duration
}

// NewCrawler 创建爬虫
func NewCrawler() *Crawler {
	return NewCrawlerWithConfig(CrawlerConfig{
		MaxDepth: 3,
		MaxPages: 100,
		Timeout:  10 * time.Second,
	})
}

// NewCrawlerWithConfig 使用配置创建爬虫
func NewCrawlerWithConfig(config CrawlerConfig) *Crawler {
	return &Crawler{
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		visited:   make(map[string]bool),
		maxDepth:  config.MaxDepth,
		maxPages:  config.MaxPages,
		timeout:   config.Timeout,
		userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	}
}

// Crawl 爬取URL
func (c *Crawler) Crawl(ctx *ScanContext, baseURL string) error {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %v", err)
	}

	ctx.Logger.Printf("Starting crawler for: %s (maxDepth: %d, maxPages: %d)", baseURL, c.maxDepth, c.maxPages)

	// 爬取队列
	queue := []crawlItem{{url: baseURL, depth: 0}}
	urlCount := 0
	
	for len(queue) > 0 && urlCount < c.maxPages {
		// 取出第一个
		item := queue[0]
		queue = queue[1:]

		// 检查是否已访问
		c.visitedLock.Lock()
		if c.visited[item.url] {
			c.visitedLock.Unlock()
			continue
		}
		c.visited[item.url] = true
		c.visitedLock.Unlock()

		// 检查深度
		if item.depth > c.maxDepth {
			continue
		}

		ctx.Logger.Printf("[Crawler] Visiting: %s (depth: %d)", item.url, item.depth)

		// 创建请求
		req, err := http.NewRequest("GET", item.url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", c.userAgent)

		// 获取页面
		resp, err := c.client.Do(req)
		if err != nil {
			ctx.Logger.Printf("[Crawler] Error fetching %s: %v", item.url, err)
			continue
		}

		// 获取状态码
		statusCode := resp.StatusCode
		contentType := resp.Header.Get("Content-Type")

		// 保存URL记录
		urlRecord := &models.CrawlerResult{
			TaskID:      ctx.Task.ID,
			URL:         item.url,
			StatusCode:  statusCode,
			ContentType: contentType,
			Method:      "GET",
			Source:      "crawler",
		}

		// 解析URL参数
		parsedURL, _ := url.Parse(item.url)
		if parsedURL.RawQuery != "" {
			urlRecord.HasParams = true
		}

		// 保存到数据库
		ctx.DB.Create(urlRecord)
		urlCount++

		// 只处理HTML内容
		if !strings.Contains(contentType, "text/html") {
			resp.Body.Close()
			continue
		}

		// 读取body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)

		// 提取链接
		links := c.extractLinks(bodyStr, item.url, parsedBase)
		for _, link := range links {
			queue = append(queue, crawlItem{url: link, depth: item.depth + 1})
		}

		// 提取并保存JS文件
		jsFiles := c.ExtractJSFiles(bodyStr, item.url)
		for _, jsURL := range jsFiles {
			// 保存JS文件URL
			jsRecord := &models.CrawlerResult{
				TaskID:      ctx.Task.ID,
				URL:         jsURL,
				ContentType: "application/javascript",
				Method:      "GET",
				Source:      "crawler_js",
			}
			ctx.DB.Create(jsRecord)
			urlCount++

			// 下载并分析JS文件
			go c.analyzeJSFile(ctx, jsURL, parsedBase.Host)
		}
	}

	ctx.Logger.Printf("[Crawler] Finished: collected %d URLs", urlCount)
	return nil
}

// crawlItem 爬取项
type crawlItem struct {
	url   string
	depth int
}

// extractLinks 提取链接
func (c *Crawler) extractLinks(body, currentURL string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	// 正则提取href
	hrefRegex := regexp.MustCompile(`href=["']([^"']+)["']`)
	matches := hrefRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		link := match[1]
		
		// 跳过特殊链接
		if strings.HasPrefix(link, "javascript:") ||
			strings.HasPrefix(link, "mailto:") ||
			strings.HasPrefix(link, "#") ||
			link == "" {
			continue
		}

		// 解析URL
		parsedLink, err := url.Parse(link)
		if err != nil {
			continue
		}

		// 转换为绝对URL
		if !parsedLink.IsAbs() {
			parsedCurrent, _ := url.Parse(currentURL)
			parsedLink = parsedCurrent.ResolveReference(parsedLink)
		}

		// 只爬取同域名的链接
		if parsedLink.Host != baseURL.Host {
			continue
		}

		// 规范化URL
		normalizedURL := parsedLink.Scheme + "://" + parsedLink.Host + parsedLink.Path
		if parsedLink.RawQuery != "" {
			normalizedURL += "?" + parsedLink.RawQuery
		}

		// 去重
		if !seen[normalizedURL] {
			seen[normalizedURL] = true
			links = append(links, normalizedURL)
		}
	}

	return links
}

// ExtractJSFiles 提取JS文件
func (c *Crawler) ExtractJSFiles(body, baseURL string) []string {
	var jsFiles []string
	seen := make(map[string]bool)

	// 提取script src
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(body, -1)

	parsedBase, _ := url.Parse(baseURL)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		src := match[1]
		parsedSrc, err := url.Parse(src)
		if err != nil {
			continue
		}

		// 转换为绝对URL
		if !parsedSrc.IsAbs() {
			parsedSrc = parsedBase.ResolveReference(parsedSrc)
		}

		jsURL := parsedSrc.String()
		if !seen[jsURL] && strings.HasSuffix(jsURL, ".js") {
			seen[jsURL] = true
			jsFiles = append(jsFiles, jsURL)
		}
	}

	return jsFiles
}

// ExtractAPIs 从JS中提取API端点
func (c *Crawler) ExtractAPIs(jsContent string) []string {
	var apis []string
	seen := make(map[string]bool)

	// API路径模式
	patterns := []string{
		`/api/[a-zA-Z0-9/_-]+`,
		`/v\d+/[a-zA-Z0-9/_-]+`,
		`['"](/[a-zA-Z0-9/_-]+)['":]`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(jsContent, -1)
		
		for _, match := range matches {
			// 清理引号
			match = strings.Trim(match, `"':`)
			if !seen[match] && strings.HasPrefix(match, "/") {
				seen[match] = true
				apis = append(apis, match)
			}
		}
	}

	return apis
}

// ExtractSubdomains 从JS中提取子域名
func (c *Crawler) ExtractSubdomains(jsContent string) []string {
	var subdomains []string
	seen := make(map[string]bool)

	// 域名模式
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+`)
	matches := domainRegex.FindAllString(jsContent, -1)

	for _, match := range matches {
		match = strings.ToLower(match)
		// 过滤掉常见的非域名
		if !strings.Contains(match, ".") || 
			strings.HasSuffix(match, ".js") ||
			strings.HasSuffix(match, ".css") ||
			strings.HasSuffix(match, ".jpg") ||
			strings.HasSuffix(match, ".png") {
			continue
		}

		if !seen[match] {
			seen[match] = true
			subdomains = append(subdomains, match)
		}
	}

	return subdomains
}

// analyzeJSFile 分析JS文件
func (c *Crawler) analyzeJSFile(ctx *ScanContext, jsURL string, baseDomain string) {
	// 下载JS文件
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	jsContent := string(body)

	// 提取API端点
	apis := c.ExtractAPIs(jsContent)
	for _, api := range apis {
		// 构建完整URL
		fullURL := jsURL
		if strings.HasPrefix(api, "/") {
			parsedJS, _ := url.Parse(jsURL)
			fullURL = parsedJS.Scheme + "://" + parsedJS.Host + api
		}

		apiRecord := &models.CrawlerResult{
			TaskID:      ctx.Task.ID,
			URL:         fullURL,
			Method:      "GET",
			Source:      "js_analysis",
			HasParams:   strings.Contains(api, "{") || strings.Contains(api, ":"),
			ContentType: "application/json",
		}
		ctx.DB.Where("task_id = ? AND url = ?", ctx.Task.ID, fullURL).FirstOrCreate(apiRecord)
	}

	// 提取子域名
	subdomains := c.ExtractSubdomains(jsContent)
	domainScanner := NewDomainScanner()
	for _, subdomain := range subdomains {
		// 验证是否属于目标域名
		if domainScanner.isSubdomainOf(subdomain, baseDomain) {
			// 保存发现的子域名
			domain := &models.Domain{
				TaskID: ctx.Task.ID,
				Domain: subdomain,
				Source: "js_analysis",
			}
			ctx.DB.Where("task_id = ? AND domain = ?", ctx.Task.ID, subdomain).FirstOrCreate(domain)
		}
	}

	// 提取敏感信息
	sensitiveInfo := c.ExtractSensitiveInfo(jsContent)
	if len(sensitiveInfo) > 0 {
		// 创建漏洞记录
		description := ""
		for key, values := range sensitiveInfo {
			if len(values) > 0 {
				description += fmt.Sprintf("%s: %d found\n", key, len(values))
			}
		}

		vuln := &models.Vulnerability{
			TaskID:      ctx.Task.ID,
			URL:         jsURL,
			Type:        "sensitive_info_leak",
			Severity:    "high",
			Title:       "JS文件中发现敏感信息",
			Description: description,
			Solution:    "移除JavaScript中的敏感信息，使用环境变量或安全的配置管理",
		}
		ctx.DB.Create(vuln)
	}
}

// ExtractSensitiveInfo 提取敏感信息
func (c *Crawler) ExtractSensitiveInfo(content string) map[string][]string {
	result := make(map[string][]string)

	// AccessKey
	accessKeyRegex := regexp.MustCompile(`(?i)(access[_-]?key|accesskey|access[_-]?id)\s*[:=]\s*['"]([a-zA-Z0-9]{16,})['"]`)
	matches := accessKeyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["access_key"] = append(result["access_key"], match[2])
		}
	}

	// SecretKey
	secretKeyRegex := regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]([a-zA-Z0-9+/]{20,})['"]`)
	matches = secretKeyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["secret_key"] = append(result["secret_key"], match[2])
		}
	}

	// API Key
	apiKeyRegex := regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9]{16,})['"]`)
	matches = apiKeyRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["api_key"] = append(result["api_key"], match[2])
		}
	}

	// Token
	tokenRegex := regexp.MustCompile(`(?i)(token|auth[_-]?token)\s*[:=]\s*['"]([a-zA-Z0-9._-]{20,})['"]`)
	matches = tokenRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 2 {
			result["token"] = append(result["token"], match[2])
		}
	}

	// 内网IP
	internalIPRegex := regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	internalIPs := internalIPRegex.FindAllString(content, -1)
	if len(internalIPs) > 0 {
		result["internal_ip"] = internalIPs
	}

	// 去重
	for key, values := range result {
		result[key] = uniqueStrings(values)
	}

	return result
}
