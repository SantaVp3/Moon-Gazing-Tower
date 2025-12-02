package service

import (
	"context"
	"log"
	"time"

	"moongazing/models"
	"moongazing/scanner/fingerprint"
	"moongazing/scanner/vulnscan"
	"moongazing/scanner/webscan"

	"go.mongodb.org/mongo-driver/bson"
)

// executeFingerprintScan 执行指纹扫描
func (e *TaskExecutor) executeFingerprintScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing fingerprint scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}


	results := make([]models.ScanResult, 0)
	fpScanner := fingerprint.NewFingerprintScanner(20)

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
	vulnScanner := vulnscan.NewVulnScanner(10)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		vulnResult := vulnScanner.ScanVuln(ctx, target, nil)
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
	contentScanner := webscan.NewContentScanner(20)

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
	contentScanner := webscan.NewContentScanner(20)

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
	
	katanaScanner := webscan.NewKatanaScanner()
	radScanner := webscan.NewRadScanner()
	
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
