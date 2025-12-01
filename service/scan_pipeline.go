package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"moongazing/models"
	"moongazing/scanner"

	"go.mongodb.org/mongo-driver/bson"
)

// ScanPipeline 扫描流水线
// 扫描流程:
// 1. 目标解析
// 2. 子域名扫描 (subfinder)
// 3. 子域名安全检测 (接管检测)
// 4. 端口扫描预处理 (CDN检测)
// 5. 端口扫描 (rustscan)
// 6. 端口指纹识别
// 7. 资产测绘 (HTTP探测)
// 8. 资产处理
// 9. URL扫描 (katana)
// 10. Web爬虫 (rad)
// 11. URL安全检测 (敏感信息)
// 12. 目录扫描
// 13. 漏洞扫描 (nuclei)
type ScanPipeline struct {
	task          *models.Task
	taskService   *TaskService
	resultService *ResultService
	ctx           context.Context
	cancel        context.CancelFunc
	
	// 扫描器
	subfinderScanner    *scanner.SubfinderScanner // 被动子域名收集
	rustScanScanner     *scanner.RustScanScanner
	katanaScanner       *scanner.KatanaScanner
	radScanner          *scanner.RadScanner
	fingerprintScanner  *scanner.FingerprintScanner
	vulnScanner         *scanner.VulnScanner
	contentScanner      *scanner.ContentScanner
	domainScanner       *scanner.DomainScanner
	httpxScanner        *scanner.HttpxScanner     // HTTP 探测器 - 用于获取子域名的 HTTP 信息
	takeoverScanner     *scanner.TakeoverScanner  // 子域名接管检测
	
	// 中间结果 (用于流水线传递)
	discoveredSubdomains []SubdomainInfo
	discoveredPorts      []PortInfo
	discoveredURLs       []URLInfo
	discoveredAssets     []AssetInfo
	
	// 统计
	totalResults int
	mu           sync.Mutex
}

// SubdomainInfo 子域名信息
type SubdomainInfo struct {
	Host         string
	Domain       string
	IPs          []string
	CNAMEs       []string
	IsCDN        bool
	CDNName      string
	Title        string   // 网页标题
	StatusCode   int      // HTTP状态码
	WebServer    string   // Web服务器
	Technologies []string // 指纹/技术栈
	URL          string   // 完整URL
}

// PortInfo 端口信息
type PortInfo struct {
	Host        string
	Port        int
	Service     string
	Version     string
	Banner      string
	Fingerprint []string
}

// URLInfo URL信息
type URLInfo struct {
	URL        string
	Method     string
	StatusCode int
	Title      string
	Source     string // katana, wayback, crawler
}

// AssetInfo 资产信息
type AssetInfo struct {
	Host        string
	Port        int
	Protocol    string // http, https
	URL         string
	Title       string
	StatusCode  int
	Server      string
	Fingerprint []string
}

// NewScanPipeline 创建扫描流水线
func NewScanPipeline(task *models.Task) *ScanPipeline {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ScanPipeline{
		task:          task,
		taskService:   NewTaskService(),
		resultService: NewResultService(),
		ctx:           ctx,
		cancel:        cancel,
		
		// 初始化扫描器 - 使用任务配置
		subfinderScanner:    scanner.NewSubfinderScanner(), // 被动子域名收集
		rustScanScanner:     createRustScannerWithTaskConfig(task),
		katanaScanner:       scanner.NewKatanaScanner(),
		radScanner:          scanner.NewRadScanner(),
		fingerprintScanner:  scanner.NewFingerprintScanner(getThreads(task, 20)),
		vulnScanner:         scanner.NewVulnScanner(getThreads(task, 10)),
		contentScanner:      scanner.NewContentScanner(getThreads(task, 20)),
		domainScanner:       scanner.NewDomainScanner(getThreads(task, 200)),
		httpxScanner:        scanner.NewHttpxScanner(getTimeout(task, 30)), // HTTP 探测器
		takeoverScanner:     scanner.NewTakeoverScanner(getThreads(task, 20)), // 子域名接管检测
		
		// 初始化结果存储
		discoveredSubdomains: make([]SubdomainInfo, 0),
		discoveredPorts:      make([]PortInfo, 0),
		discoveredURLs:       make([]URLInfo, 0),
		discoveredAssets:     make([]AssetInfo, 0),
	}
}

// createRustScannerWithTaskConfig 根据任务配置创建 RustScan 扫描器
func createRustScannerWithTaskConfig(task *models.Task) *scanner.RustScanScanner {
	config := &scanner.RustScanConfig{
		Timeout:   task.Config.Timeout,
		BatchSize: task.Config.Threads,     // 并发数 -> BatchSize
		RateLimit: task.Config.PortScanRate,
	}
	
	// 如果配置为空，使用默认值
	if config.Timeout <= 0 {
		config.Timeout = 30 // 默认30秒
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 4500 // 默认4500
	}
	
	log.Printf("[Pipeline] RustScan config: timeout=%ds, batchSize=%d, rateLimit=%d", 
		config.Timeout, config.BatchSize, config.RateLimit)
	
	return scanner.NewRustScanScannerWithConfig(config)
}

// getThreads 获取配置的线程数，如果未设置则使用默认值
func getThreads(task *models.Task, defaultVal int) int {
	if task.Config.Threads > 0 {
		return task.Config.Threads
	}
	return defaultVal
}

// getTimeout 获取配置的超时时间，如果未设置则使用默认值
func getTimeout(task *models.Task, defaultVal int) int {
	if task.Config.Timeout > 0 {
		return task.Config.Timeout
	}
	return defaultVal
}

// Run 执行完整扫描流水线
func (p *ScanPipeline) Run() error {
	startTime := time.Now()
	log.Printf("[Pipeline] Starting full scan pipeline for task: %s", p.task.ID.Hex())
	
	// 获取启用的扫描类型
	scanTypes := p.task.Config.ScanTypes
	if len(scanTypes) == 0 {
		scanTypes = []string{"port_scan"} // 默认只做端口扫描
	}
	
	scanTypesMap := make(map[string]bool)
	for _, t := range scanTypes {
		scanTypesMap[t] = true
	}
	
	totalSteps := p.calculateTotalSteps(scanTypesMap)
	currentStep := 0
	
	// 1. 目标解析
	p.updateProgress(currentStep, totalSteps, "解析目标...")
	targets := p.parseTargets()
	currentStep++
	
	// 2. 子域名扫描
	if scanTypesMap["subdomain"] {
		p.updateProgress(currentStep, totalSteps, "子域名扫描...")
		p.runSubdomainScan(targets)
		currentStep++
	}
	
	// 2.5 子域名接管检测 (在子域名扫描后进行)
	if scanTypesMap["subdomain"] || scanTypesMap["takeover"] {
		p.updateProgress(currentStep, totalSteps, "子域名接管检测...")
		p.runSubdomainTakeover()
		currentStep++
	}
	
	// 3. 端口扫描预处理 (CDN检测)
	if scanTypesMap["port_scan"] {
		p.updateProgress(currentStep, totalSteps, "CDN检测...")
		p.runCDNDetection()
		currentStep++
	}
	
	// 4. 端口扫描
	if scanTypesMap["port_scan"] {
		p.updateProgress(currentStep, totalSteps, "端口扫描...")
		p.runPortScan()
		currentStep++
	}
	
	// 5. 端口指纹识别
	if scanTypesMap["fingerprint"] || scanTypesMap["service_detect"] {
		p.updateProgress(currentStep, totalSteps, "指纹识别...")
		p.runFingerprint()
		currentStep++
	}
	
	// 6. 资产测绘 (HTTP探测)
	if scanTypesMap["port_scan"] || scanTypesMap["fingerprint"] {
		p.updateProgress(currentStep, totalSteps, "资产测绘...")
		p.runAssetMapping()
		currentStep++
	}
	
	// 7. URL扫描 (katana + wayback)
	if scanTypesMap["crawler"] {
		p.updateProgress(currentStep, totalSteps, "URL扫描...")
		p.runURLScan()
		currentStep++
	}
	
	// 8. Web爬虫 (rad)
	if scanTypesMap["crawler"] {
		p.updateProgress(currentStep, totalSteps, "Web爬虫...")
		p.runWebCrawler()
		currentStep++
	}
	
	// 9. 目录扫描
	if scanTypesMap["dir_scan"] {
		p.updateProgress(currentStep, totalSteps, "目录扫描...")
		p.runDirScan()
		currentStep++
	}
	
	// 10. 漏洞扫描
	if scanTypesMap["vuln_scan"] {
		p.updateProgress(currentStep, totalSteps, "漏洞扫描...")
		p.runVulnScan()
		currentStep++
	}
	
	// 完成
	duration := time.Since(startTime)
	log.Printf("[Pipeline] Scan completed in %s, total results: %d", duration, p.totalResults)
	
	p.completeTask()
	return nil
}

// calculateTotalSteps 计算总步骤数
func (p *ScanPipeline) calculateTotalSteps(scanTypes map[string]bool) int {
	steps := 1 // 目标解析
	if scanTypes["subdomain"] {
		steps++
	}
	if scanTypes["subdomain"] || scanTypes["takeover"] {
		steps++ // 子域名接管检测
	}
	if scanTypes["port_scan"] {
		steps += 2 // CDN检测 + 端口扫描
	}
	if scanTypes["fingerprint"] || scanTypes["service_detect"] {
		steps++
	}
	if scanTypes["port_scan"] || scanTypes["fingerprint"] {
		steps++ // 资产测绘
	}
	if scanTypes["crawler"] {
		steps += 2 // URL扫描 + Web爬虫
	}
	if scanTypes["dir_scan"] {
		steps++
	}
	if scanTypes["vuln_scan"] {
		steps++
	}
	return steps
}

// parseTargets 解析目标
func (p *ScanPipeline) parseTargets() []string {
	targets := p.task.Targets
	result := make([]string, 0)
	
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		
		// 处理 CIDR (如 192.168.1.0/24)
		if strings.Contains(target, "/") {
			// TODO: 展开 CIDR
			result = append(result, target)
		} else {
			result = append(result, target)
		}
	}
	
	log.Printf("[Pipeline] Parsed %d targets", len(result))
	return result
}

// runSubdomainScan 执行子域名扫描
// 使用 subfinder (被动收集) + 内置扫描器 (主动爆破)
func (p *ScanPipeline) runSubdomainScan(targets []string) {
	log.Printf("[Pipeline] Running subdomain scan for %d targets", len(targets))
	
	for _, target := range targets {
		// 跳过 IP 地址
		if isIPAddress(target) {
			p.discoveredSubdomains = append(p.discoveredSubdomains, SubdomainInfo{
				Host:   target,
				Domain: target,
				IPs:    []string{target},
			})
			continue
		}
		
		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Minute)
		
		// 步骤1: 使用 subfinder 被动收集子域名
		log.Printf("[Pipeline] Step 1: Subfinder passive collection for %s", target)
		subfinderResult, err := p.subfinderScanner.Scan(ctx, target)
		if err != nil {
			log.Printf("[Pipeline] Subfinder error: %v", err)
		}
		
		// 收集所有子域名
		collectedSubdomains := make([]string, 0)
		if subfinderResult != nil {
			collectedSubdomains = subfinderResult.GetUniqueSubdomains()
			log.Printf("[Pipeline] Subfinder found %d subdomains for %s", len(collectedSubdomains), target)
		}
		
		// 添加原始域名到列表
		collectedSubdomains = append(collectedSubdomains, target)
		
		cancel()
		
		// 步骤2: 处理结果 - 使用 httpx 丰富子域名信息
		if len(collectedSubdomains) > 0 {
			log.Printf("[Pipeline] Enriching %d subdomains with HTTP info for %s", len(collectedSubdomains), target)
			
			// 使用 httpx 批量探测子域名，获取 IP、Title、StatusCode、CDN、指纹等信息
			ctx2, cancel2 := context.WithTimeout(p.ctx, 10*time.Minute)
			httpxResults := p.httpxScanner.EnrichSubdomains(ctx2, collectedSubdomains)
			cancel2()
			
			for _, result := range httpxResults {
				subInfo := SubdomainInfo{
					Host:         result.Host,
					Domain:       target,
					IPs:          result.IPs,
					IsCDN:        result.CDN,
					CDNName:      result.CDNName,
					Title:        result.Title,
					StatusCode:   result.StatusCode,
					WebServer:    result.WebServer,
					Technologies: result.Technologies,
					URL:          result.URL,
				}
				p.discoveredSubdomains = append(p.discoveredSubdomains, subInfo)
				
				// 保存到数据库（包含完整信息）
				p.saveEnrichedSubdomainResult(subInfo, target)
			}
		} else {
			// 回退：使用内置的子域名字典
			log.Printf("[Pipeline] Fallback to built-in subdomain scan for %s", target)
			ctx2, cancel2 := context.WithTimeout(p.ctx, 5*time.Minute)
			scanResult := p.domainScanner.QuickSubdomainScan(ctx2, target)
			cancel2()
			for _, sub := range scanResult.Subdomains {
				subInfo := SubdomainInfo{
					Host:   sub.FullDomain,
					Domain: target,
					IPs:    sub.IPs,
					CNAMEs: sub.CNAMEs,
					IsCDN:  sub.CDN,
				}
				if sub.CDN {
					subInfo.CDNName = sub.CDNProvider
				}
				p.discoveredSubdomains = append(p.discoveredSubdomains, subInfo)
				p.saveSubdomainResult(sub, target)
			}
		}
	}
	
	log.Printf("[Pipeline] Discovered %d subdomains total", len(p.discoveredSubdomains))
}

// runSubdomainTakeover 执行子域名接管检测
// 检测子域名是否存在被接管的风险（如 CNAME 指向已失效的云服务）
func (p *ScanPipeline) runSubdomainTakeover() {
	log.Printf("[Pipeline] Running subdomain takeover detection")
	
	// 获取所有子域名
	subdomains := make([]string, 0)
	if len(p.discoveredSubdomains) > 0 {
		for _, sub := range p.discoveredSubdomains {
			// 跳过 IP 地址
			if !isIPAddress(sub.Host) {
				subdomains = append(subdomains, sub.Host)
			}
		}
	} else {
		// 如果没有发现子域名，使用原始目标
		for _, target := range p.task.Targets {
			if !isIPAddress(target) {
				subdomains = append(subdomains, target)
			}
		}
	}
	
	if len(subdomains) == 0 {
		log.Printf("[Pipeline] No subdomains to check for takeover")
		return
	}
	
	log.Printf("[Pipeline] Checking %d subdomains for takeover vulnerabilities", len(subdomains))
	
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Minute)
	defer cancel()
	
	results, err := p.takeoverScanner.ScanBatch(ctx, subdomains)
	if err != nil {
		log.Printf("[Pipeline] Takeover scan error: %v", err)
		return
	}
	
	vulnerableCount := 0
	for _, result := range results {
		if result.Vulnerable {
			vulnerableCount++
			log.Printf("[Pipeline] Found vulnerable subdomain: %s (Service: %s, CNAME: %s)", 
				result.Domain, result.Service, result.CNAME)
			
			// 保存接管检测结果
			p.saveTakeoverResult(result)
		}
	}
	
	log.Printf("[Pipeline] Takeover detection completed: %d vulnerable out of %d checked", 
		vulnerableCount, len(subdomains))
}

// saveTakeoverResult 保存子域名接管检测结果
func (p *ScanPipeline) saveTakeoverResult(result *scanner.TakeoverResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	scanResult := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeTakeover,
		Source:      "takeover_scanner",
		Data: bson.M{
			"subdomain":    result.Domain,
			"cname":        result.CNAME,
			"provider":     result.Service,
			"vulnerable":   result.Vulnerable,
			"fingerprints": result.Fingerprints,
			"reason":       result.Reason,
			"discussion":   result.Discussion,
			"severity":     "high", // 子域名接管通常是高危漏洞
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResult(&scanResult)
	p.totalResults++
}

// runCDNDetection 执行CDN检测
func (p *ScanPipeline) runCDNDetection() {
	log.Printf("[Pipeline] Running CDN detection")
	
	// 过滤掉 CDN 的子域名，避免扫描 CDN
	nonCDNHosts := make([]SubdomainInfo, 0)
	for _, sub := range p.discoveredSubdomains {
		if !sub.IsCDN {
			nonCDNHosts = append(nonCDNHosts, sub)
		} else {
			log.Printf("[Pipeline] Skipping CDN host: %s (%s)", sub.Host, sub.CDNName)
		}
	}
	
	// 如果没有子域名结果，使用原始目标
	if len(p.discoveredSubdomains) == 0 {
		for _, target := range p.task.Targets {
			p.discoveredSubdomains = append(p.discoveredSubdomains, SubdomainInfo{
				Host:   target,
				Domain: target,
			})
		}
	}
	
	log.Printf("[Pipeline] %d hosts after CDN filter", len(nonCDNHosts))
}

// runPortScan 执行端口扫描
func (p *ScanPipeline) runPortScan() {
	// 确定要扫描的目标
	targets := make([]string, 0)
	
	if len(p.discoveredSubdomains) > 0 {
		// 扫描发现的子域名
		for _, sub := range p.discoveredSubdomains {
			if !sub.IsCDN {
				targets = append(targets, sub.Host)
			}
		}
	} else {
		// 扫描原始目标
		targets = p.task.Targets
	}
	
	log.Printf("[Pipeline] Running port scan for %d targets", len(targets))
	
	// 检查 RustScan 是否可用
	if !p.rustScanScanner.IsAvailable() {
		log.Printf("[Pipeline] RustScan not available, skipping port scan")
		return
	}
	
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Minute)
		
		var scanResult *scanner.ScanResult
		var err error
		
		portScanMode := p.task.Config.PortScanMode
		if portScanMode == "" {
			portScanMode = "quick"
		}
		
		switch portScanMode {
		case "full":
			log.Printf("[Pipeline] Full port scan on %s", target)
			scanResult, err = p.rustScanScanner.FullScan(ctx, target)
		case "top1000":
			log.Printf("[Pipeline] Top1000 port scan on %s", target)
			scanResult, err = p.rustScanScanner.Top1000Scan(ctx, target)
		case "custom":
			customPorts := p.task.Config.PortRange
			if customPorts == "" {
				customPorts = "1-1000"
			}
			log.Printf("[Pipeline] Custom port scan (%s) on %s", customPorts, target)
			scanResult, err = p.rustScanScanner.ScanPorts(ctx, target, customPorts)
		default:
			log.Printf("[Pipeline] Quick port scan on %s", target)
			scanResult, err = p.rustScanScanner.QuickScan(ctx, target)
		}
		cancel()
		
		if err != nil {
			log.Printf("[Pipeline] RustScan error on %s: %v", target, err)
			continue
		}
		
		if scanResult == nil {
			continue
		}
		
		// 保存结果
		for _, port := range scanResult.Ports {
			if port.State == "open" {
				portInfo := PortInfo{
					Host:    target,
					Port:    port.Port,
					Service: port.Service,
					Version: port.Version,
					Banner:  port.Banner,
				}
				p.discoveredPorts = append(p.discoveredPorts, portInfo)
				
				// 保存到数据库
				p.savePortResult(port, target)
			}
		}
	}
	
	log.Printf("[Pipeline] Discovered %d open ports", len(p.discoveredPorts))
}

// runFingerprint 执行指纹识别
func (p *ScanPipeline) runFingerprint() {
	log.Printf("[Pipeline] Running fingerprint scan")
	
	// 对发现的 HTTP/HTTPS 端口进行指纹识别
	for _, port := range p.discoveredPorts {
		if isHTTPPort(port.Port) {
			protocol := "http"
			if port.Port == 443 || port.Port == 8443 {
				protocol = "https"
			}
			
			url := fmt.Sprintf("%s://%s:%d", protocol, port.Host, port.Port)
			
			ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
			fpResult := p.fingerprintScanner.ScanFingerprint(ctx, url)
			cancel()
			
			// 更新端口信息
			fingerprints := make([]string, 0)
			for _, fp := range fpResult.Fingerprints {
				fingerprints = append(fingerprints, fp.Name)
				p.saveFingerprintResult(fp, url)
			}
			
			// 添加到资产
			asset := AssetInfo{
				Host:        port.Host,
				Port:        port.Port,
				Protocol:    protocol,
				URL:         url,
				Fingerprint: fingerprints,
			}
			p.discoveredAssets = append(p.discoveredAssets, asset)
		}
	}
	
	log.Printf("[Pipeline] Discovered %d assets", len(p.discoveredAssets))
}

// runAssetMapping 执行资产测绘
func (p *ScanPipeline) runAssetMapping() {
	log.Printf("[Pipeline] Running asset mapping")
	
	// 对发现的端口进行 HTTP 探测
	for i := range p.discoveredAssets {
		asset := &p.discoveredAssets[i]
		
		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
		fpResult := p.fingerprintScanner.ScanFingerprint(ctx, asset.URL)
		cancel()
		
		if fpResult != nil {
			asset.Title = fpResult.Title
			asset.StatusCode = fpResult.StatusCode
			asset.Server = fpResult.Server
		}
	}
}

// runURLScan 执行URL扫描 (使用 Katana)
func (p *ScanPipeline) runURLScan() {
	log.Printf("[Pipeline] Running URL scan with Katana")
	
	// 获取要爬取的 URL
	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}
	
	// 如果没有资产，使用原始目标
	if len(urls) == 0 {
		for _, target := range p.task.Targets {
			if strings.HasPrefix(target, "http") {
				urls = append(urls, target)
			} else {
				urls = append(urls, "https://"+target)
			}
		}
	}
	
	// 使用 Katana 爬取
	if p.katanaScanner.IsAvailable() {
		for _, url := range urls {
			ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.katanaScanner.ExecutionTimeout)*time.Minute)
			
			result, err := p.katanaScanner.Crawl(ctx, url)
			cancel()
			
			if err != nil {
				log.Printf("[Pipeline] Katana failed for %s: %v", url, err)
				continue
			}
			
			for _, crawledURL := range result.URLs {
				urlInfo := URLInfo{
					URL:        crawledURL.URL,
					Method:     crawledURL.Method,
					StatusCode: crawledURL.StatusCode,
					Source:     "katana",
				}
				p.discoveredURLs = append(p.discoveredURLs, urlInfo)
				p.saveURLResult(crawledURL, url)
			}
		}
	}
	
	log.Printf("[Pipeline] Discovered %d URLs", len(p.discoveredURLs))
}

// runWebCrawler 执行Web爬虫 (使用 Rad)
func (p *ScanPipeline) runWebCrawler() {
	log.Printf("[Pipeline] Running web crawler with Rad")
	
	if !p.radScanner.IsAvailable() {
		log.Printf("[Pipeline] Rad not available, skipping")
		return
	}
	
	// 获取要爬取的 URL
	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}
	
	for _, url := range urls {
		ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.radScanner.ExecutionTimeout)*time.Minute)
		
		result, err := p.radScanner.Crawl(ctx, url)
		cancel()
		
		if err != nil {
			log.Printf("[Pipeline] Rad failed for %s: %v", url, err)
			continue
		}
		
		for _, crawledURL := range result.URLs {
			// 避免重复
			exists := false
			for _, existing := range p.discoveredURLs {
				if existing.URL == crawledURL.URL {
					exists = true
					break
				}
			}
			
			if !exists {
				urlInfo := URLInfo{
					URL:    crawledURL.URL,
					Method: crawledURL.Method,
					Source: "rad",
				}
				p.discoveredURLs = append(p.discoveredURLs, urlInfo)
			}
		}
	}
	
	log.Printf("[Pipeline] Total URLs after Rad: %d", len(p.discoveredURLs))
}

// runDirScan 执行目录扫描
func (p *ScanPipeline) runDirScan() {
	log.Printf("[Pipeline] Running directory scan")
	
	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}
	
	for _, url := range urls {
		ctx, cancel := context.WithTimeout(p.ctx, 5*time.Minute)
		result := p.contentScanner.QuickDirScan(ctx, url)
		cancel()
		
		for _, entry := range result.Results {
			p.saveDirScanResult(entry, url)
		}
	}
}

// runVulnScan 执行漏洞扫描
func (p *ScanPipeline) runVulnScan() {
	log.Printf("[Pipeline] Running vulnerability scan")
	
	// 收集所有需要扫描的目标
	targets := make([]string, 0)
	
	// 添加资产
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			targets = append(targets, asset.URL)
		}
	}
	
	// 添加发现的 URL
	for _, urlInfo := range p.discoveredURLs {
		targets = append(targets, urlInfo.URL)
	}
	
	// 去重
	targets = uniqueStrings(targets)
	
	log.Printf("[Pipeline] Scanning %d targets for vulnerabilities", len(targets))
	
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Minute)
		result := p.vulnScanner.ScanVuln(ctx, target, nil)
		cancel()
		
		for _, vuln := range result.Vulns {
			p.saveVulnResult(vuln, target)
		}
	}
}

// 辅助方法 - 保存结果

func (p *ScanPipeline) saveSubdomainResult(sub scanner.SubdomainResult, domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	ips := ""
	if len(sub.IPs) > 0 {
		ips = sub.IPs[0]
	}
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      "pipeline",
		Data: bson.M{
			"subdomain":    sub.Subdomain,
			"domain":       domain,
			"full_domain":  sub.FullDomain,
			"ip":           ips,
			"ips":          sub.IPs,
			"cnames":       sub.CNAMEs,
			"alive":        sub.Alive,
			"cdn":          sub.CDN,
			"cdn_provider": sub.CDNProvider,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveUnverifiedSubdomainResult 保存子域名结果
func (p *ScanPipeline) saveUnverifiedSubdomainResult(subdomain, domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      "subfinder",
		Data: bson.M{
			"subdomain":   subdomain,
			"domain":      domain,
			"full_domain": subdomain,
			"verified":    false,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveEnrichedSubdomainResult 保存丰富后的子域名结果（包含 IP、Title、StatusCode、CDN、指纹等）
func (p *ScanPipeline) saveEnrichedSubdomainResult(subInfo SubdomainInfo, domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	ip := ""
	if len(subInfo.IPs) > 0 {
		ip = subInfo.IPs[0]
	}
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      "httpx",
		Data: bson.M{
			"subdomain":    subInfo.Host,
			"domain":       domain,
			"full_domain":  subInfo.Host,
			"ip":           ip,
			"ips":          subInfo.IPs,
			"cdn":          subInfo.IsCDN,
			"cdn_provider": subInfo.CDNName,
			"title":        subInfo.Title,
			"status_code":  subInfo.StatusCode,
			"web_server":   subInfo.WebServer,
			"fingerprint":  subInfo.Technologies,
			"url":          subInfo.URL,
			"is_alive":     subInfo.StatusCode > 0,
			"verified":     true,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

func (p *ScanPipeline) savePortResult(port scanner.PortResult, host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypePort,
		Source:      "pipeline",
		Data: bson.M{
			"ip":      host,
			"host":    host,
			"port":    port.Port,
			"service": port.Service,
			"state":   port.State,
			"version": port.Version,
			"banner":  port.Banner,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

func (p *ScanPipeline) saveFingerprintResult(fp scanner.Fingerprint, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeService,
		Source:      "pipeline",
		Data: bson.M{
			"target":     target,
			"name":       fp.Name,
			"version":    fp.Version,
			"category":   fp.Category,
			"confidence": fp.Confidence,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

func (p *ScanPipeline) saveURLResult(url scanner.KatanaCrawledURL, source string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeCrawler,
		Source:      source,
		Data: bson.M{
			"url":         url.URL,
			"method":      url.Method,
			"status_code": url.StatusCode,
			"crawler":     source,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

func (p *ScanPipeline) saveDirScanResult(entry scanner.DirEntry, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeDirScan,
		Source:      "pipeline",
		Data: bson.M{
			"target":       target,
			"url":          entry.URL,
			"path":         entry.Path,
			"status":       entry.StatusCode,
			"size":         entry.ContentLength,
			"content_type": entry.ContentType,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

func (p *ScanPipeline) saveVulnResult(vuln scanner.VulnResult, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeVuln,
		Source:      "pipeline",
		Data: bson.M{
			"target":      target,
			"name":        vuln.Name,
			"severity":    vuln.Severity,
			"description": vuln.Description,
			"vuln_id":     vuln.VulnID,
			"evidence":    vuln.Evidence,
			"matched_at":  vuln.MatchedAt,
		},
		CreatedAt: time.Now(),
	}
	
	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// updateProgress 更新进度
func (p *ScanPipeline) updateProgress(current, total int, message string) {
	progress := int((float64(current) / float64(total)) * 100)
	if progress > 100 {
		progress = 100
	}
	
	log.Printf("[Pipeline] Progress: %d%% - %s", progress, message)
	
	p.taskService.UpdateTask(p.task.ID.Hex(), map[string]interface{}{
		"progress": progress,
	})
}

// completeTask 完成任务
func (p *ScanPipeline) completeTask() {
	p.taskService.UpdateTask(p.task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusCompleted,
		"progress":     100,
		"completed_at": time.Now(),
		"result_stats": bson.M{
			"total_results":      p.totalResults,
			"discovered_assets":  len(p.discoveredAssets),
			"discovered_ports":   len(p.discoveredPorts),
			"discovered_urls":    len(p.discoveredURLs),
			"discovered_subdomains": len(p.discoveredSubdomains),
		},
	})
	
	log.Printf("[Pipeline] Task %s completed with %d results", p.task.ID.Hex(), p.totalResults)
}

// failTask 任务失败
func (p *ScanPipeline) failTask(errMsg string) {
	p.taskService.UpdateTask(p.task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusFailed,
		"completed_at": time.Now(),
		"last_error":   errMsg,
	})
	
	log.Printf("[Pipeline] Task %s failed: %s", p.task.ID.Hex(), errMsg)
}

// 辅助函数

func isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func isHTTPPort(port int) bool {
	httpPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true,
		8000: true, 8888: true, 9000: true, 9090: true,
		3000: true, 5000: true, 8001: true, 8002: true,
	}
	return httpPorts[port]
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ScanConfig 扫描配置 (从任务配置中提取)
type ScanConfig struct {
	ScanTypes []string
}
