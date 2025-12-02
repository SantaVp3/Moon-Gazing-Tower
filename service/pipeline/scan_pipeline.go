package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"moongazing/config"
	"moongazing/models"
	"moongazing/scanner/fingerprint"
	"moongazing/scanner/portscan"
	"moongazing/scanner/subdomain"
	"moongazing/scanner/subdomain/thirdparty"
	"moongazing/scanner/vulnscan"
	"moongazing/scanner/webscan"
)

// ScanPipeline 扫描流水线
// 整合多种扫描工具，执行完整的资产发现和漏洞扫描流程
type ScanPipeline struct {
	task          *models.Task
	ctx           context.Context
	cancel        context.CancelFunc
	taskService   TaskService
	resultService ResultService

	// 扫描器
	domainScanner      *subdomain.DomainScanner
	subfinderScanner   *subdomain.SubfinderScanner
	httpxScanner       *webscan.HttpxScanner
	rustScanScanner    *portscan.RustScanScanner
	katanaScanner      *webscan.KatanaScanner
	radScanner         *webscan.RadScanner
	fingerprintScanner *fingerprint.FingerprintScanner
	contentScanner     *webscan.ContentScanner
	vulnScanner        *vulnscan.VulnScanner
	takeoverScanner    *subdomain.TakeoverScanner

	// 第三方数据源管理器
	thirdpartyManager *thirdparty.APIManager

	// 结果收集
	discoveredSubdomains []SubdomainInfo
	discoveredPorts      []PortInfo
	discoveredAssets     []AssetInfo
	discoveredURLs       []URLInfo
	totalResults         int

	mu sync.Mutex
}

// SubdomainInfo 子域名信息
type SubdomainInfo struct {
	Host         string
	Domain       string
	IPs          []string
	CNAMEs       []string
	IsCDN        bool
	CDNName      string
	Title        string
	StatusCode   int
	WebServer    string
	Technologies []string
	URL          string
}

// PortInfo 端口信息
type PortInfo struct {
	Host    string
	Port    int
	Service string
	Version string
	Banner  string
}

// AssetInfo 资产信息
type AssetInfo struct {
	Host        string
	Port        int
	Protocol    string
	URL         string
	Title       string
	StatusCode  int
	Server      string
	Fingerprint []string
}

// URLInfo URL信息
type URLInfo struct {
	URL        string
	Method     string
	StatusCode int
	Source     string
}

// NewScanPipeline 创建扫描流水线
func NewScanPipeline(task *models.Task, taskService TaskService, resultService ResultService) *ScanPipeline {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建第三方数据源管理器
	cfg := config.GetConfig()
	apiConfig := &thirdparty.APIConfig{
		FofaEmail: cfg.ThirdParty.Fofa.Email,
		FofaKey:   cfg.ThirdParty.Fofa.Key,
		HunterKey: cfg.ThirdParty.Hunter.Key,
		QuakeKey:  cfg.ThirdParty.Quake.Key,
	}
	thirdpartyManager := thirdparty.NewAPIManager(apiConfig)

	log.Printf("[Pipeline] Third-party API manager created, configured sources: %v", thirdpartyManager.GetConfiguredSources())

	return &ScanPipeline{
		task:               task,
		ctx:                ctx,
		cancel:             cancel,
		taskService:        taskService,
		resultService:      resultService,
		domainScanner:      subdomain.NewDomainScanner(10),
		subfinderScanner:   subdomain.NewSubfinderScanner(),
		httpxScanner:       webscan.NewHttpxScanner(10),
		rustScanScanner:    portscan.NewRustScanScanner(),
		katanaScanner:      webscan.NewKatanaScanner(),
		radScanner:         webscan.NewRadScanner(),
		fingerprintScanner: fingerprint.NewFingerprintScanner(10),
		contentScanner:     webscan.NewContentScanner(10),
		vulnScanner:        vulnscan.NewVulnScanner(10),
		takeoverScanner:    subdomain.NewTakeoverScanner(10),
		thirdpartyManager:  thirdpartyManager,
	}
}

// Stop 停止流水线
func (p *ScanPipeline) Stop() {
	p.cancel()
}

// Run 执行扫描流水线
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
