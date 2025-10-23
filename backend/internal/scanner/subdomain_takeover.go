package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// SubdomainTakeoverScanner 子域名接管检测器
type SubdomainTakeoverScanner struct {
	client           *http.Client
	dnsTimeout       time.Duration
	httpTimeout      time.Duration
	fingerprints     []TakeoverFingerprint
}

// TakeoverFingerprint 接管指纹
type TakeoverFingerprint struct {
	Service      string   // 服务名称 (如: GitHub Pages, AWS S3, Heroku)
	CNAMEPattern []string // CNAME 匹配模式
	ResponseCode []int    // HTTP 状态码
	BodyKeywords []string // 响应体关键字
	Description  string   // 描述信息
	Severity     string   // 严重程度: high, medium, low
}

// TakeoverResult 接管检测结果
type TakeoverResult struct {
	Domain      string
	Vulnerable  bool
	Service     string
	CNAME       string
	Evidence    string
	Severity    string
	Description string
}

// NewSubdomainTakeoverScanner 创建子域名接管检测器
func NewSubdomainTakeoverScanner() *SubdomainTakeoverScanner {
	return &SubdomainTakeoverScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 不跟随重定向
			},
		},
		dnsTimeout:   5 * time.Second,
		httpTimeout:  10 * time.Second,
		fingerprints: initTakeoverFingerprints(),
	}
}

// initTakeoverFingerprints 初始化接管指纹库
func initTakeoverFingerprints() []TakeoverFingerprint {
	return []TakeoverFingerprint{
		// GitHub Pages
		{
			Service:      "GitHub Pages",
			CNAMEPattern: []string{"github.io", "github.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"There isn't a GitHub Pages site here",
				"For root URLs (like http://example.com/) you must provide an index.html file",
			},
			Description: "子域名CNAME指向GitHub Pages但页面不存在",
			Severity:    "high",
		},
		// AWS S3
		{
			Service:      "AWS S3",
			CNAMEPattern: []string{"s3.amazonaws.com", "s3-website"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"NoSuchBucket",
				"The specified bucket does not exist",
			},
			Description: "S3存储桶已被删除或不存在",
			Severity:    "high",
		},
		// Heroku
		{
			Service:      "Heroku",
			CNAMEPattern: []string{"herokuapp.com", "herokussl.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"No such app",
				"There's nothing here, yet",
			},
			Description: "Heroku应用不存在",
			Severity:    "high",
		},
		// Azure
		{
			Service:      "Azure",
			CNAMEPattern: []string{"azurewebsites.net", "cloudapp.azure.com", "azure.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"404 Web Site not found",
				"Error 404",
			},
			Description: "Azure服务不存在",
			Severity:    "high",
		},
		// Shopify
		{
			Service:      "Shopify",
			CNAMEPattern: []string{"myshopify.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Sorry, this shop is currently unavailable",
				"Only one step left!",
			},
			Description: "Shopify店铺不存在",
			Severity:    "medium",
		},
		// Fastly
		{
			Service:      "Fastly",
			CNAMEPattern: []string{"fastly.net"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Fastly error: unknown domain",
			},
			Description: "Fastly CDN配置错误",
			Severity:    "medium",
		},
		// Ghost
		{
			Service:      "Ghost",
			CNAMEPattern: []string{"ghost.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The thing you were looking for is no longer here",
			},
			Description: "Ghost博客不存在",
			Severity:    "medium",
		},
		// Pantheon
		{
			Service:      "Pantheon",
			CNAMEPattern: []string{"pantheonsite.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"404 error unknown site!",
			},
			Description: "Pantheon站点不存在",
			Severity:    "high",
		},
		// Tumblr
		{
			Service:      "Tumblr",
			CNAMEPattern: []string{"tumblr.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Whatever you were looking for doesn't currently exist at this address",
				"There's nothing here.",
			},
			Description: "Tumblr博客不存在",
			Severity:    "low",
		},
		// WordPress.com
		{
			Service:      "WordPress.com",
			CNAMEPattern: []string{"wordpress.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Do you want to register",
			},
			Description: "WordPress站点不存在",
			Severity:    "low",
		},
		// Bitbucket
		{
			Service:      "Bitbucket",
			CNAMEPattern: []string{"bitbucket.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Repository not found",
			},
			Description: "Bitbucket仓库不存在",
			Severity:    "medium",
		},
		// Cargo
		{
			Service:      "Cargo",
			CNAMEPattern: []string{"cargocollective.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"404 Not Found",
			},
			Description: "Cargo站点不存在",
			Severity:    "low",
		},
		// Feedpress
		{
			Service:      "Feedpress",
			CNAMEPattern: []string{"redirect.feedpress.me"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The feed has not been found",
			},
			Description: "Feedpress订阅不存在",
			Severity:    "low",
		},
		// StatusPage
		{
			Service:      "StatusPage",
			CNAMEPattern: []string{"statuspage.io"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"You are being",
				"redirected",
			},
			Description: "StatusPage页面不存在",
			Severity:    "medium",
		},
		// Unbounce
		{
			Service:      "Unbounce",
			CNAMEPattern: []string{"unbouncepages.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The requested URL was not found on this server",
			},
			Description: "Unbounce页面不存在",
			Severity:    "medium",
		},
		// Surge.sh
		{
			Service:      "Surge.sh",
			CNAMEPattern: []string{"surge.sh"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"project not found",
			},
			Description: "Surge项目不存在",
			Severity:    "high",
		},
		// Vercel
		{
			Service:      "Vercel",
			CNAMEPattern: []string{"vercel.app", "now.sh"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"The deployment could not be found on Vercel",
				"DEPLOYMENT_NOT_FOUND",
			},
			Description: "Vercel部署不存在",
			Severity:    "high",
		},
		// Netlify
		{
			Service:      "Netlify",
			CNAMEPattern: []string{"netlify.app", "netlify.com"},
			ResponseCode: []int{404},
			BodyKeywords: []string{
				"Not Found - Request ID:",
			},
			Description: "Netlify站点不存在",
			Severity:    "high",
		},
	}
}

// Scan 执行子域名接管检测
func (s *SubdomainTakeoverScanner) Scan(ctx *ScanContext) error {
	// 🆕 加载扫描器配置
	scannerConfig := LoadScannerConfig(ctx)
	
	var domains []models.Domain
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&domains)

	ctx.Logger.Printf("=== Subdomain Takeover Scan Started ===")
	ctx.Logger.Printf("Checking %d domains for potential takeover vulnerabilities", len(domains))

	// 🆕 使用配置的并发数
	concurrency := scannerConfig.SubdomainTakeoverConcurrency
	ctx.Logger.Printf("[Config] Subdomain takeover scanner: concurrency=%d", concurrency)
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	resultChan := make(chan *TakeoverResult, len(domains))

	for _, domain := range domains {
		wg.Add(1)
		go func(d models.Domain) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := s.checkDomain(d.Domain)
			if result != nil {
				resultChan <- result
			}
		}(domain)
	}

	// 等待所有检测完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 保存结果
	vulnerableCount := 0
	for result := range resultChan {
		if result.Vulnerable {
			s.saveResult(ctx, result)
			vulnerableCount++
			ctx.Logger.Printf("⚠️  VULNERABLE: %s -> %s (%s)", result.Domain, result.Service, result.Severity)
		}
	}

	ctx.Logger.Printf("Subdomain takeover scan completed: %d vulnerable domains found", vulnerableCount)
	return nil
}

// checkDomain 检查单个域名是否存在接管风险
func (s *SubdomainTakeoverScanner) checkDomain(domain string) *TakeoverResult {
	// 1. 检查CNAME记录
	cname, err := s.getCNAME(domain)
	if err != nil || cname == "" {
		return nil // 没有CNAME，跳过
	}

	// 2. 匹配指纹
	for _, fp := range s.fingerprints {
		if s.matchCNAME(cname, fp.CNAMEPattern) {
			// 3. HTTP请求验证
			if s.verifyTakeover(domain, &fp) {
				return &TakeoverResult{
					Domain:      domain,
					Vulnerable:  true,
					Service:     fp.Service,
					CNAME:       cname,
					Evidence:    fmt.Sprintf("CNAME: %s", cname),
					Severity:    fp.Severity,
					Description: fp.Description,
				}
			}
		}
	}

	return nil
}

// getCNAME 获取域名的CNAME记录
func (s *SubdomainTakeoverScanner) getCNAME(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.dnsTimeout)
	defer cancel()

	cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
	if err != nil {
		return "", err
	}

	// 去掉末尾的点
	cname = strings.TrimSuffix(cname, ".")
	
	// 如果CNAME和域名相同，说明没有CNAME记录
	if cname == domain {
		return "", nil
	}

	return cname, nil
}

// matchCNAME 检查CNAME是否匹配指纹模式
func (s *SubdomainTakeoverScanner) matchCNAME(cname string, patterns []string) bool {
	cnameLower := strings.ToLower(cname)
	for _, pattern := range patterns {
		if strings.Contains(cnameLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// verifyTakeover 通过HTTP请求验证是否存在接管风险
func (s *SubdomainTakeoverScanner) verifyTakeover(domain string, fp *TakeoverFingerprint) bool {
	// 尝试HTTP和HTTPS
	schemes := []string{"https", "http"}
	
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		
		resp, err := s.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// 检查状态码
		codeMatch := false
		for _, code := range fp.ResponseCode {
			if resp.StatusCode == code {
				codeMatch = true
				break
			}
		}

		if !codeMatch {
			continue
		}

		// 检查响应体关键字
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		bodyStr := string(body)
		for _, keyword := range fp.BodyKeywords {
			if strings.Contains(bodyStr, keyword) {
				return true
			}
		}
	}

	return false
}

// saveResult 保存检测结果到数据库
func (s *SubdomainTakeoverScanner) saveResult(ctx *ScanContext, result *TakeoverResult) {
	// 更新域名记录，添加接管标记
	ctx.DB.Model(&models.Domain{}).
		Where("task_id = ? AND domain = ?", ctx.Task.ID, result.Domain).
		Updates(map[string]interface{}{
			"takeover_vulnerable": true,
			"takeover_service":    result.Service,
			"takeover_cname":      result.CNAME,
			"takeover_severity":   result.Severity,
		})

	// 可选：创建单独的漏洞记录表
	// vulnerability := &models.Vulnerability{
	// 	TaskID:      ctx.Task.ID,
	// 	Type:        "subdomain_takeover",
	// 	Target:      result.Domain,
	// 	Service:     result.Service,
	// 	Severity:    result.Severity,
	// 	Description: result.Description,
	// 	Evidence:    result.Evidence,
	// }
	// ctx.DB.Create(vulnerability)
}

