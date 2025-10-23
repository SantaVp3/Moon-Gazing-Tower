package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// SiteScanner 站点扫描器
type SiteScanner struct {
	client      *http.Client
	crawler     *Crawler
	fingerprint bool
}

// NewSiteScanner 创建站点扫描器
func NewSiteScanner() *SiteScanner {
	// 初始化指纹库
	InitFingerprints()

	return &SiteScanner{
		client: &http.Client{
			Timeout: 5 * time.Second, // 优化：降低HTTP超时时间到5秒
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        100,              // 优化：增加连接池
				MaxIdleConnsPerHost: 10,               // 优化：增加每个host的连接数
				IdleConnTimeout:     30 * time.Second, // 优化：连接复用
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		crawler:     NewCrawler(),
		fingerprint: true,
	}
}

// Detect 识别站点
func (ss *SiteScanner) Detect(ctx *ScanContext) error {
	// 🆕 加载扫描器配置
	scannerConfig := LoadScannerConfig(ctx)
	ss.client.Timeout = scannerConfig.SiteTimeout

	// 🆕 使用配置重新创建爬虫
	ss.crawler = NewCrawlerWithConfig(CrawlerConfig{
		MaxDepth: scannerConfig.CrawlerMaxDepth,
		MaxPages: scannerConfig.CrawlerMaxPages,
		Timeout:  scannerConfig.SiteTimeout,
	})

	var ports []models.Port
	ctx.DB.Where("task_id = ? AND port IN (?)", ctx.Task.ID, []int{80, 443, 8080, 8443, 8888, 8000, 8001, 9090}).Find(&ports)

	ctx.Logger.Printf("Detecting sites for %d ports", len(ports))

	// 🆕 使用配置的并发数
	concurrency := scannerConfig.SiteConcurrency
	if len(ports) < concurrency {
		concurrency = len(ports)
	}
	ctx.Logger.Printf("[Config] Site scanner: concurrency=%d, timeout=%v, crawler_depth=%d, crawler_pages=%d",
		concurrency, ss.client.Timeout, scannerConfig.CrawlerMaxDepth, scannerConfig.CrawlerMaxPages)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, port := range ports {
		// 检查任务是否被取消
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Site detection cancelled by user")
			wg.Wait()
			return ctx.Ctx.Err()
		default:
		}

		wg.Add(1)
		go func(p models.Port) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 检查取消状态
			select {
			case <-ctx.Ctx.Done():
				return
			default:
			}

			ss.detectSiteForPort(ctx, p)
		}(port)
	}

	wg.Wait()
	ctx.Logger.Printf("Site detection completed")
	return nil
}

// detectSiteForPort 检测单个端口的站点
func (ss *SiteScanner) detectSiteForPort(ctx *ScanContext, port models.Port) {
	schemes := []string{"http"}
	if port.Port == 443 || port.Port == 8443 {
		schemes = []string{"https"}
	} else if port.Port == 80 || port.Port == 8080 || port.Port == 8888 {
		// 尝试两种协议
		schemes = []string{"http", "https"}
	}

	// 查找该IP对应的域名
	var domains []models.Domain
	ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, port.IPAddress).Find(&domains)

	// 优先使用域名，如果没有域名则使用IP
	hosts := make([]string, 0)
	for _, domain := range domains {
		hosts = append(hosts, domain.Domain)
	}
	if len(hosts) == 0 {
		hosts = append(hosts, port.IPAddress)
	}

	for _, host := range hosts {
		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s:%d", scheme, host, port.Port)

			if siteInfo := ss.probeSite(url); siteInfo != nil {
				siteInfo.TaskID = ctx.Task.ID
				ctx.DB.Create(siteInfo)
				ctx.Logger.Printf("Site detected: %s - %s", url, siteInfo.Title)

				// 如果启用了爬虫
				if ctx.Task.Options.EnableCrawler {
					ss.crawlSite(ctx, url)
				}

				break // 成功后不再尝试其他协议
			}
		}
	}
}

// probeSite 探测站点
func (ss *SiteScanner) probeSite(url string) *models.Site {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	// 设置User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := ss.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 读取body用于指纹识别
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	bodyStr := string(body)

	// 提取标题
	title := ExtractTitle(bodyStr)

	// 获取所有headers
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// 指纹识别
	fingerprints := MatchFingerprints(headers, bodyStr, title)

	// 合并指纹为字符串
	fingerprintStr := ""
	if len(fingerprints) > 0 {
		fingerprintStr = fingerprints[0]
		for i := 1; i < len(fingerprints) && i < 5; i++ { // 最多显示5个
			fingerprintStr += ", " + fingerprints[i]
		}
	}

	// CDN检测
	isCDN := IsCDN(headers, "")

	// 从URL中提取IP
	ip := ExtractIPFromURL(url)

	site := &models.Site{
		URL:          url,
		StatusCode:   resp.StatusCode,
		IP:           ip, // 添加IP
		ContentType:  resp.Header.Get("Content-Type"),
		Server:       resp.Header.Get("Server"),
		Title:        title,
		Fingerprint:  fingerprintStr, // 添加单个指纹字符串
		Fingerprints: fingerprints,   // 保留数组
	}

	// 记录CDN信息到Server字段
	if isCDN {
		site.Server += " [CDN]"
	}

	return site
}

// crawlSite 爬取站点
func (ss *SiteScanner) crawlSite(ctx *ScanContext, url string) {
	ctx.Logger.Printf("Starting crawler for site: %s", url)

	// 使用任务选项配置爬虫
	config := CrawlerConfig{
		MaxDepth: 3,
		MaxPages: 100,
		Timeout:  10 * time.Second,
	}

	// 如果任务选项中有爬虫配置，使用它们
	if ctx.Task.Options.CrawlerDepth > 0 {
		config.MaxDepth = ctx.Task.Options.CrawlerDepth
	}
	if ctx.Task.Options.CrawlerPages > 0 {
		config.MaxPages = ctx.Task.Options.CrawlerPages
	}

	crawler := NewCrawlerWithConfig(config)
	err := crawler.Crawl(ctx, url)
	if err != nil {
		ctx.Logger.Printf("[Crawler] Failed for %s: %v", url, err)
		return
	}

	ctx.Logger.Printf("[Crawler] Completed for %s", url)
}

// TakeScreenshots 站点截图
func (ss *SiteScanner) TakeScreenshots(ctx *ScanContext) error {
	var sites []models.Site
	if err := ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return fmt.Errorf("failed to fetch sites: %w", err)
	}

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites to screenshot")
		return nil
	}

	ctx.Logger.Printf("Taking screenshots for %d sites", len(sites))

	// 创建截图扫描器
	screenshotDir := "./data/screenshots"
	screenshotScanner := NewScreenshotScanner(screenshotDir)

	// 并发截图（限制并发数为3，避免资源占用过高）
	concurrency := 3
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	successCount := 0
	failCount := 0
	var mu sync.Mutex

	for _, site := range sites {
		wg.Add(1)
		go func(s models.Site) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			ctx.Logger.Printf("Taking screenshot: %s", s.URL)

			// 使用可视区域截图（更快）
			screenshotPath, err := screenshotScanner.ScreenshotViewport(s.URL)
			if err != nil {
				ctx.Logger.Printf("Screenshot failed for %s: %v", s.URL, err)
				mu.Lock()
				failCount++
				mu.Unlock()
				return
			}

			// 只保存文件名，不保存完整路径
			filename := filepath.Base(screenshotPath)

			// 更新数据库中的截图路径
			if err := ctx.DB.Model(&models.Site{}).
				Where("id = ?", s.ID).
				Update("screenshot", filename).Error; err != nil {
				ctx.Logger.Printf("Failed to update screenshot path for %s: %v", s.URL, err)
				mu.Lock()
				failCount++
				mu.Unlock()
				return
			}

			ctx.Logger.Printf("Screenshot saved: %s -> %s", s.URL, filename)
			mu.Lock()
			successCount++
			mu.Unlock()
		}(site)
	}

	wg.Wait()

	ctx.Logger.Printf("Screenshot completed: %d success, %d failed", successCount, failCount)
	return nil
}

// CheckFileLeaks 文件泄露检测
func (ss *SiteScanner) CheckFileLeaks(ctx *ScanContext) error {
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	ctx.Logger.Printf("Checking file leaks for %d sites", len(sites))

	// 敏感文件路径
	leakPaths := []struct {
		path     string
		severity string
		desc     string
	}{
		{"/.git/config", "high", "Git配置文件泄露"},
		{"/.git/HEAD", "high", "Git仓库泄露"},
		{"/.env", "critical", "环境变量文件泄露"},
		{"/.env.local", "high", "本地环境配置泄露"},
		{"/.env.production", "high", "生产环境配置泄露"},
		{"/web.config", "medium", "IIS配置文件泄露"},
		{"/.DS_Store", "low", "Mac系统文件泄露"},
		{"/backup.zip", "high", "备份文件泄露"},
		{"/backup.tar.gz", "high", "备份文件泄露"},
		{"/backup.sql", "critical", "数据库备份泄露"},
		{"/db.sql", "critical", "数据库文件泄露"},
		{"/database.sql", "critical", "数据库文件泄露"},
		{"/.svn/entries", "high", "SVN信息泄露"},
		{"/phpinfo.php", "medium", "PHP信息泄露"},
		{"/info.php", "medium", "PHP信息泄露"},
		{"/test.php", "low", "测试文件泄露"},
		{"/config.php", "high", "配置文件泄露"},
		{"/config.json", "high", "配置文件泄露"},
		{"/config.yml", "high", "配置文件泄露"},
		{"/config.yaml", "high", "配置文件泄露"},
		{"/settings.py", "high", "Django配置泄露"},
		{"/application.properties", "high", "Spring配置泄露"},
		{"/application.yml", "high", "Spring配置泄露"},
		{"/.htaccess", "medium", "Apache配置泄露"},
		{"/robots.txt", "info", "Robots文件"},
		{"/sitemap.xml", "info", "站点地图"},
		{"/README.md", "low", "README文件泄露"},
		{"/CHANGELOG.md", "low", "变更日志泄露"},
	}

	for _, site := range sites {
		for _, leak := range leakPaths {
			url := site.URL + leak.path

			statusCode, contentType, size := ss.checkURLDetailed(url)
			if statusCode == 200 && size > 0 {
				vuln := &models.Vulnerability{
					TaskID:      ctx.Task.ID,
					URL:         url,
					Type:        "file_leak",
					Severity:    leak.severity,
					Title:       leak.desc,
					Description: fmt.Sprintf("发现敏感文件: %s (大小: %d bytes, 类型: %s)", url, size, contentType),
					Solution:    "删除或限制对敏感文件的访问",
				}
				ctx.DB.Create(vuln)
				ctx.Logger.Printf("File leak found: %s [%s]", url, leak.severity)
			}
		}
	}

	return nil
}

// checkURLDetailed 详细检查URL
func (ss *SiteScanner) checkURLDetailed(url string) (int, string, int64) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", 0
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := ss.client.Do(req)
	if err != nil {
		return 0, "", 0
	}
	defer resp.Body.Close()

	// 读取body获取大小
	body, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, resp.Header.Get("Content-Type"), int64(len(body))
}

// RunNuclei 已废弃 - 使用智能PoC检测替代
func (ss *SiteScanner) RunNuclei(ctx *ScanContext) error {
	ctx.Logger.Printf("RunNuclei is deprecated, use smart PoC detection instead")
	return nil
}
