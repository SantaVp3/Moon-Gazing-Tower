package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"moongazing/database"
	"moongazing/models"
	"moongazing/scanner"

	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
)

// TaskExecutor 任务执行器
type TaskExecutor struct {
	taskService *TaskService
	workers     int
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// NewTaskExecutor 创建任务执行器
func NewTaskExecutor(workers int) *TaskExecutor {
	if workers <= 0 {
		workers = 5
	}
	return &TaskExecutor{
		taskService: NewTaskService(),
		workers:     workers,
		stopCh:      make(chan struct{}),
	}
}

// Start 启动执行器
func (e *TaskExecutor) Start() {
	taskTypes := []string{
		string(models.TaskTypeFull),
		string(models.TaskTypeSubdomain),
		string(models.TaskTypeTakeover),
		string(models.TaskTypePortScan),
		string(models.TaskTypeFingerprint),
		string(models.TaskTypeVulnScan),
		string(models.TaskTypeDirScan),
		string(models.TaskTypeCrawler),
	}

	for i := 0; i < e.workers; i++ {
		for _, taskType := range taskTypes {
			e.wg.Add(1)
			go e.worker(i, taskType)
		}
	}

	log.Printf("[TaskExecutor] Started %d workers for %d task types", e.workers, len(taskTypes))
}

// Stop 停止执行器
func (e *TaskExecutor) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	log.Println("[TaskExecutor] Stopped")
}

// worker 工作者循环
func (e *TaskExecutor) worker(id int, taskType string) {
	defer e.wg.Done()
	workerID := fmt.Sprintf("worker-%d-%s", id, taskType)
	log.Printf("[%s] Worker started, listening for %s tasks", workerID, taskType)

	for {
		select {
		case <-e.stopCh:
			return
		default:
		}

		// 从队列获取任务
		task, err := e.dequeueRunningTask(taskType)
		if err != nil {
			if err != redis.Nil {
				log.Printf("[%s] Dequeue error: %v", workerID, err)
			}
			time.Sleep(1 * time.Second)
			continue
		}

		if task == nil {
			time.Sleep(1 * time.Second)
			continue
		}

		// 处理任务
		log.Printf("[%s] Processing task: %s", workerID, task.ID.Hex())
		e.processTask(task)
	}
}

// dequeueRunningTask 获取正在运行的任务
func (e *TaskExecutor) dequeueRunningTask(taskType string) (*models.Task, error) {
	ctx := context.Background()
	rdb := database.GetRedis()

	queueKey := "task:queue:" + taskType
	result, err := rdb.LPop(ctx, queueKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// 获取任务
	task, err := e.taskService.GetTaskByID(result)
	if err != nil {
		return nil, err
	}

	// 只处理 running 状态的任务
	if task.Status != models.TaskStatusRunning {
		return nil, nil
	}

	return task, nil
}

// processTask 处理任务
func (e *TaskExecutor) processTask(task *models.Task) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TaskExecutor] Panic in task %s: %v", task.ID.Hex(), r)
			e.failTask(task, "内部错误")
		}
	}()

	// 对于 full 类型的任务，使用流水线扫描
	if task.Type == models.TaskTypeFull {
		pipeline := NewScanPipeline(task)
		if err := pipeline.Run(); err != nil {
			e.failTask(task, err.Error())
		}
		return
	}

	// 根据任务类型执行不同的扫描
	switch task.Type {
	case models.TaskTypeSubdomain:
		e.executeSubdomainScan(task)
	case models.TaskTypeTakeover:
		e.executeTakeoverScan(task)
	case models.TaskTypePortScan:
		e.executePortScan(task)
	case models.TaskTypeFingerprint:
		e.executeFingerprintScan(task)
	case models.TaskTypeVulnScan:
		e.executeVulnScan(task)
	case models.TaskTypeDirScan:
		e.executeContentScan(task)
	case models.TaskTypeCrawler:
		e.executeCrawlerScan(task)
	default:
		e.failTask(task, "未知的任务类型: "+string(task.Type))
	}
}

// executeSubdomainScan 执行子域名扫描
func (e *TaskExecutor) executeSubdomainScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing subdomain scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	
	// 初始化扫描器
	subfinderScanner := scanner.NewSubfinderScanner()
	domainScanner := scanner.NewDomainScanner(200)
	httpxScanner := scanner.NewHttpxScanner(30) // 添加 httpx 扫描器
	
	log.Printf("[TaskExecutor] Using subfinder for passive subdomain collection")

	for i, target := range targets {
		// 更新进度
		progress := int((float64(i) / float64(len(targets))) * 50) // 子域名收集占 50%
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
		collectedSubdomains := make([]string, 0)
		
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
				collectedSubdomains = append(collectedSubdomains, sub.FullDomain)
			}
		} else if subfinderResult != nil {
			collectedSubdomains = subfinderResult.GetUniqueSubdomains()
			log.Printf("[TaskExecutor] Subfinder found %d subdomains for %s", len(collectedSubdomains), target)
		}
		
		// 添加原始域名
		collectedSubdomains = append(collectedSubdomains, target)
		
		// 使用 httpx 丰富子域名信息（获取 IP、标题、状态码、CDN、指纹等）
		log.Printf("[TaskExecutor] Enriching %d subdomains with HTTP info using httpx", len(collectedSubdomains))
		e.updateProgress(task, 50+int((float64(i)/float64(len(targets)))*40)) // httpx 探测占 40%
		
		ctx3, cancel3 := context.WithTimeout(context.Background(), 15*time.Minute)
		httpxResults := httpxScanner.EnrichSubdomains(ctx3, collectedSubdomains)
		cancel3()
		
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

	// 保存结果
	e.saveResults(task, results)
	e.completeTask(task, len(results))
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
	
	// 初始化扫描器
	takeoverScanner := scanner.NewTakeoverScanner(20)
	
	// 收集所有要检测的子域名
	allSubdomains := make([]string, 0)
	
	for i, target := range targets {
		// 更新进度
		progress := int((float64(i) / float64(len(targets))) * 50)
		e.updateProgress(task, progress)
		
		// 跳过 IP 地址
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
	
	// 批量检测接管漏洞
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	
	e.updateProgress(task, 50)
	
	takeoverResults, err := takeoverScanner.ScanBatch(ctx, allSubdomains)
	if err != nil {
		log.Printf("[TaskExecutor] Takeover scan error: %v", err)
	}
	
	e.updateProgress(task, 90)
	
	// 处理结果
	for _, tr := range takeoverResults {
		if tr.Vulnerable {
			log.Printf("[TaskExecutor] Found vulnerable subdomain: %s (Service: %s)", 
				tr.Domain, tr.Service)
			
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
	
	// 保存结果
	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// executePortScan 执行端口扫描
func (e *TaskExecutor) executePortScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing port scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	
	// 使用 RustScan 进行端口扫描 - 传递任务配置
	rustConfig := &scanner.RustScanConfig{
		Timeout:   task.Config.Timeout,
		BatchSize: task.Config.Threads, // 并发数
		RateLimit: task.Config.PortScanRate,
	}
	if rustConfig.Timeout <= 0 {
		rustConfig.Timeout = 30 // 默认30秒
	}
	if rustConfig.BatchSize <= 0 {
		rustConfig.BatchSize = 4500
	}
	
	rustScanner := scanner.NewRustScanScannerWithConfig(rustConfig)
	if !rustScanner.IsAvailable() {
		e.failTask(task, "RustScan 工具不可用，请先安装 RustScan")
		return
	}
	
	log.Printf("[TaskExecutor] Using RustScan for port scanning, config: timeout=%ds, batch=%d",
		rustConfig.Timeout, rustConfig.BatchSize)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		
		var scanResult *scanner.ScanResult
		var err error
		
		// 根据配置选择端口扫描模式
		portScanMode := task.Config.PortScanMode
		if portScanMode == "" {
			portScanMode = "quick" // 默认快速扫描
		}
		
		switch portScanMode {
		case "full":
			log.Printf("[TaskExecutor] Running full port scan (1-65535) on %s", target)
			scanResult, err = rustScanner.FullScan(ctx, target)
		case "top1000":
			log.Printf("[TaskExecutor] Running top 1000 port scan on %s", target)
			scanResult, err = rustScanner.Top1000Scan(ctx, target)
		case "custom":
			customPorts := task.Config.PortRange
			if customPorts == "" {
				customPorts = "1-1000" // 默认端口范围
			}
			log.Printf("[TaskExecutor] Running custom port scan (%s) on %s", customPorts, target)
			scanResult, err = rustScanner.ScanPorts(ctx, target, customPorts)
		default: // "quick"
			log.Printf("[TaskExecutor] Running quick port scan on %s", target)
			scanResult, err = rustScanner.QuickScan(ctx, target)
		}
		cancel()
		
		if err != nil {
			log.Printf("[TaskExecutor] RustScan error on %s: %v", target, err)
			continue
		}
		
		if scanResult == nil {
			continue
		}

		for _, port := range scanResult.Ports {
			if port.State == "open" {
				result := models.ScanResult{
					TaskID:      task.ID,
					WorkspaceID: task.WorkspaceID,
					Type:        models.ResultTypePort,
					Source:      "主动扫描",
					Data: bson.M{
						"host":        target,
						"port":        port.Port,
						"service":     port.Service,
						"state":       port.State,
						"version":     port.Version,
						"banner":      port.Banner,
						"fingerprint": port.Fingerprint,
					},
					CreatedAt: time.Now(),
				}
				results = append(results, result)
			}
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// executeFingerprintScan 执行指纹扫描
func (e *TaskExecutor) executeFingerprintScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing fingerprint scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	fpScanner := scanner.NewFingerprintScanner(20)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		fpResult := fpScanner.ScanFingerprint(ctx, target)
		cancel()

		for _, fp := range fpResult.Fingerprints {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeService,
				Source:      "主动扫描",
				Data: bson.M{
					"target":     target,
					"name":       fp.Name,
					"version":    fp.Version,
					"category":   fp.Category,
					"confidence": fp.Confidence,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// executeVulnScan 执行漏洞扫描
func (e *TaskExecutor) executeVulnScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing vuln scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	vulnScanner := scanner.NewVulnScanner(10)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		vulnResult := vulnScanner.ScanVuln(ctx, target, nil) // nil uses default templates
		cancel()

		for _, vuln := range vulnResult.Vulns {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeVuln,
				Source:      "主动扫描",
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
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// executeContentScan 执行目录扫描
func (e *TaskExecutor) executeContentScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing content scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	contentScanner := scanner.NewContentScanner(20)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		dirResult := contentScanner.QuickDirScan(ctx, target)
		cancel()

		for _, entry := range dirResult.Results {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeDirScan,
				Source:      "主动扫描",
				Data: bson.M{
					"target":       target,
					"url":          entry.URL,
					"path":         entry.Path,
					"status":       entry.StatusCode,
					"size":         entry.ContentLength,
					"content_type": entry.ContentType,
					"title":        entry.Title,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// executeSensitiveScan 执行敏感信息扫描
func (e *TaskExecutor) executeSensitiveScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing sensitive scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	contentScanner := scanner.NewContentScanner(20)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		sensitiveResult := contentScanner.ScanSensitiveInfo(ctx, target)
		cancel()

		for _, finding := range sensitiveResult.Findings {
			result := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeSensitive,
				Source:      "主动扫描",
				Data: bson.M{
					"target":   target,
					"type":     finding.Type,
					"pattern":  finding.Pattern,
					"matches":  finding.Matches,
					"location": finding.Location,
					"severity": finding.Severity,
				},
				CreatedAt: time.Now(),
			}
			results = append(results, result)
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// executeCrawlerScan 执行爬虫扫描 (Katana + Rad)
func (e *TaskExecutor) executeCrawlerScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing crawler scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	results := make([]models.ScanResult, 0)
	
	// 使用 Katana 爬虫
	katanaScanner := scanner.NewKatanaScanner()
	radScanner := scanner.NewRadScanner()
	
	useKatana := katanaScanner.IsAvailable()
	useRad := radScanner.IsAvailable()
	
	if useKatana {
		log.Printf("[TaskExecutor] Using Katana for web crawling")
	}
	if useRad {
		log.Printf("[TaskExecutor] Using Rad for web crawling")
	}

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		// Katana 爬取
		if useKatana {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(katanaScanner.ExecutionTimeout)*time.Minute)
			katanaResult, err := katanaScanner.Crawl(ctx, target)
			cancel()

			if err == nil {
				for _, url := range katanaResult.URLs {
					result := models.ScanResult{
						TaskID:      task.ID,
						WorkspaceID: task.WorkspaceID,
						Type:        models.ResultTypeCrawler,
						Source:      "katana",
						Data: bson.M{
							"target":      target,
							"url":         url.URL,
							"method":      url.Method,
							"status_code": url.StatusCode,
							"crawler":     "katana",
						},
						CreatedAt: time.Now(),
					}
					results = append(results, result)
				}
			} else {
				log.Printf("[TaskExecutor] Katana failed for %s: %v", target, err)
			}
		}

		// Rad 爬取
		if useRad {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(radScanner.ExecutionTimeout)*time.Minute)
			radResult, err := radScanner.Crawl(ctx, target)
			cancel()

			if err == nil {
				for _, url := range radResult.URLs {
					result := models.ScanResult{
						TaskID:      task.ID,
						WorkspaceID: task.WorkspaceID,
						Type:        models.ResultTypeCrawler,
						Source:      "rad",
						Data: bson.M{
							"target":  target,
							"url":     url.URL,
							"method":  url.Method,
							"crawler": "rad",
						},
						CreatedAt: time.Now(),
					}
					results = append(results, result)
				}
			} else {
				log.Printf("[TaskExecutor] Rad failed for %s: %v", target, err)
			}
		}
	}

	e.saveResults(task, results)
	e.completeTask(task, len(results))
}

// updateProgress 更新任务进度
func (e *TaskExecutor) updateProgress(task *models.Task, progress int) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"progress": progress,
	})
}

// saveResults 保存扫描结果
func (e *TaskExecutor) saveResults(task *models.Task, results []models.ScanResult) {
	resultService := NewResultService()
	for _, result := range results {
		if err := resultService.CreateResult(&result); err != nil {
			log.Printf("[TaskExecutor] Failed to save result: %v", err)
		}
	}
}

// completeTask 完成任务
func (e *TaskExecutor) completeTask(task *models.Task, resultCount int) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusCompleted,
		"progress":     100,
		"completed_at": time.Now(),
		"result_count": resultCount,
	})
	log.Printf("[TaskExecutor] Task %s completed with %d results", task.ID.Hex(), resultCount)
}

// failTask 任务失败
func (e *TaskExecutor) failTask(task *models.Task, errMsg string) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusFailed,
		"completed_at": time.Now(),
		"error":        errMsg,
	})
	log.Printf("[TaskExecutor] Task %s failed: %s", task.ID.Hex(), errMsg)
}
