package service

import (
	"context"
	"log"
	"time"

	"moongazing/config"
	"moongazing/models"
	"moongazing/scanner/subdomain"
	"moongazing/scanner/webscan"
	"moongazing/scanner/subdomain/thirdparty"

	"go.mongodb.org/mongo-driver/bson"
)

// executeSubdomainScan 执行子域名扫描
func (e *TaskExecutor) executeSubdomainScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing subdomain scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	// 首先为每个非IP目标创建根域名记录
	results := make([]models.ScanResult, 0)
	
	// 初始化扫描器
	subfinderScanner := subdomain.NewSubfinderScanner()
	domainScanner := subdomain.NewDomainScanner(200)
	httpxScanner := webscan.NewHttpxScanner(30)
	
	// 从配置文件读取第三方 API 密钥，自动创建管理器
	thirdpartyManager := e.createThirdpartyManager()
	
	log.Printf("[TaskExecutor] Using subfinder for passive subdomain collection")

	for i, target := range targets {
		// 更新进度
		progress := int((float64(i) / float64(len(targets))) * 50)
		e.updateProgress(task, progress)

		// 跳过 IP 地址
		if isIPAddress(target) {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSubdomain,
				Source:      "直接输入",
				Data: bson.M{
					"subdomain":   target,
					"domain":      target,
					"full_domain": target,
					"ip":          target,
					"ips":         []string{target},
					"alive":       true,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
			continue
		}

		// 收集子域名
		subdomainSet := e.collectSubdomains(target, subfinderScanner, domainScanner, thirdpartyManager)
		
		log.Printf("[TaskExecutor] Total unique subdomains collected: %d for %s", len(subdomainSet), target)
		
		// 转换为切片
		collectedSubdomains := make([]string, 0, len(subdomainSet))
		for sub := range subdomainSet {
			collectedSubdomains = append(collectedSubdomains, sub)
		}
		
		// 使用 httpx 丰富子域名信息
		log.Printf("[TaskExecutor] Enriching %d subdomains with HTTP info using httpx", len(collectedSubdomains))
		e.updateProgress(task, 50+int((float64(i)/float64(len(targets)))*40))
		
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		httpxResults := httpxScanner.EnrichSubdomains(ctx, collectedSubdomains)
		cancel()
		
		log.Printf("[TaskExecutor] Httpx enriched %d subdomains", len(httpxResults))
		
		for _, httpResult := range httpxResults {
			ip := ""
			if len(httpResult.IPs) > 0 {
				ip = httpResult.IPs[0]
			}
			
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSubdomain,
				Source:      "subfinder+httpx",
				Data: bson.M{
					"subdomain":    httpResult.Host,
					"domain":       target,
					"full_domain":  httpResult.Host,
					"url":          httpResult.URL,
					"ip":           ip,
					"ips":          httpResult.IPs,
					"title":        httpResult.Title,
					"status_code":  httpResult.StatusCode,
					"web_server":   httpResult.WebServer,
					"technologies": httpResult.Technologies,
					"cdn":          httpResult.CDN,
					"cdn_name":     httpResult.CDNName,
					"alive":        httpResult.StatusCode > 0,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// collectSubdomains 收集子域名（被动枚举 + 第三方API）
func (e *TaskExecutor) collectSubdomains(target string, subfinderScanner *subdomain.SubfinderScanner, domainScanner *subdomain.DomainScanner, thirdpartyManager *thirdparty.APIManager) map[string]bool {
	subdomainSet := make(map[string]bool)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	
	// 使用 subfinder 被动收集子域名
	log.Printf("[TaskExecutor] Subfinder scanning %s", target)
	subfinderResult, err := subfinderScanner.Scan(ctx, target)
	cancel()
	
	if err != nil {
		log.Printf("[TaskExecutor] Subfinder error: %v, fallback to built-in scanner", err)
		
		// 回退: 使用内置扫描器
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Minute)
		scanResult := domainScanner.QuickSubdomainScan(ctx2, target)
		cancel2()
		for _, sub := range scanResult.Subdomains {
			subdomainSet[sub.FullDomain] = true
		}
	} else if subfinderResult != nil {
		for _, sub := range subfinderResult.GetUniqueSubdomains() {
			subdomainSet[sub] = true
		}
		log.Printf("[TaskExecutor] Subfinder found %d subdomains for %s", len(subfinderResult.GetUniqueSubdomains()), target)
	}
	
	// 使用第三方 API 收集子域名
	if thirdpartyManager != nil {
		log.Printf("[TaskExecutor] Collecting subdomains from third-party APIs for %s", target)
		sources := thirdpartyManager.GetConfiguredSources()
		log.Printf("[TaskExecutor] Using third-party sources: %v", sources)
		
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Minute)
		thirdpartyResult := thirdpartyManager.CollectSubdomains(ctx2, target, sources, 500)
		cancel2()
		
		if thirdpartyResult != nil {
			for _, sub := range thirdpartyResult.Subdomains {
				subdomainSet[sub] = true
			}
			log.Printf("[TaskExecutor] Third-party APIs found %d subdomains for %s (sources: %v)", 
				thirdpartyResult.TotalFound, target, thirdpartyResult.Sources)
		}
	}
	
	// 添加原始域名
	subdomainSet[target] = true
	
	return subdomainSet
}

// createThirdpartyManager 创建第三方API管理器
func (e *TaskExecutor) createThirdpartyManager() *thirdparty.APIManager {
	cfg := config.GetConfig()
	apiConfig := &thirdparty.APIConfig{
		FofaEmail: cfg.ThirdParty.Fofa.Email,
		FofaKey:   cfg.ThirdParty.Fofa.Key,
		HunterKey: cfg.ThirdParty.Hunter.Key,
		QuakeKey:  cfg.ThirdParty.Quake.Key,
	}
	
	if apiConfig.FofaKey != "" || apiConfig.HunterKey != "" || apiConfig.QuakeKey != "" {
		manager := thirdparty.NewAPIManager(apiConfig)
		configuredSources := manager.GetConfiguredSources()
		log.Printf("[TaskExecutor] Third-party API auto-enabled with sources: %v", configuredSources)
		return manager
	}
	return nil
}

// executeTakeoverScan 执行子域名接管检测扫描
func (e *TaskExecutor) executeTakeoverScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing takeover scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	takeoverScanner := subdomain.NewTakeoverScanner(20)
	
	// 收集所有要检测的子域名
	allSubdomains := make([]string, 0)
	
	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 50)
		e.updateProgress(task, progress)
		
		if isIPAddress(target) {
			continue
		}
		allSubdomains = append(allSubdomains, target)
	}
	
	if len(allSubdomains) == 0 {
		e.failTask(task, "没有有效的域名目标")
		return
	}
	
	log.Printf("[TaskExecutor] Checking %d domains for takeover vulnerabilities", len(allSubdomains))
	
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	
	e.updateProgress(task, 50)
	
	takeoverResults, err := takeoverScanner.ScanBatch(ctx, allSubdomains)
	if err != nil {
		log.Printf("[TaskExecutor] Takeover scan error: %v", err)
	}
	
	e.updateProgress(task, 90)
	
	for _, tr := range takeoverResults {
		if tr.Vulnerable {
			log.Printf("[TaskExecutor] Found vulnerable subdomain: %s (Service: %s)", tr.Domain, tr.Service)
			
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeTakeover,
				Source:      "takeover_scanner",
				Data: bson.M{
					"subdomain":    tr.Domain,
					"cname":        tr.CNAME,
					"provider":     tr.Service,
					"vulnerable":   tr.Vulnerable,
					"fingerprints": tr.Fingerprints,
					"reason":       tr.Reason,
					"discussion":   tr.Discussion,
					"severity":     "high",
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}
	
	log.Printf("[TaskExecutor] Takeover scan completed: %d vulnerable domains found", len(results))
	
	e.saveResults(task, results)
	e.completeTask(task, len(results))
}
