package service

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"moongazing/database"
	"moongazing/models"
	"moongazing/service/notify"

	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
)

// TaskExecutor 任务执行器
type TaskExecutor struct {
	taskService   *TaskService
	resultService *ResultService
	workers       int
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewTaskExecutor 创建任务执行器
func NewTaskExecutor(workers int) *TaskExecutor {
	if workers <= 0 {
		workers = 5
	}
	return &TaskExecutor{
		taskService:   NewTaskService(),
		resultService: NewResultService(),
		workers:       workers,
		stopCh:        make(chan struct{}),
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

		log.Printf("[%s] Processing task: %s", workerID, task.ID.Hex())
		e.processTask(task)
	}
}

// dequeueRunningTask 获取待执行的任务
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

	task, err := e.taskService.GetTaskByID(result)
	if err != nil {
		return nil, err
	}

	// 接受 Pending 或 Running 状态的任务
	if task.Status != models.TaskStatusRunning && task.Status != models.TaskStatusPending {
		return nil, nil
	}

	// 如果任务是 Pending 状态，更新为 Running
	if task.Status == models.TaskStatusPending {
		e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
			"status":     models.TaskStatusRunning,
			"started_at": time.Now(),
		})
		task.Status = models.TaskStatusRunning
		log.Printf("[TaskExecutor] Task %s started (was pending)", task.ID.Hex())
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

	// 使用 StreamingPipeline 处理所有扫描任务
	switch task.Type {
	case models.TaskTypeFull:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   15,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: true,
			PortScan:               true,
			PortScanMode:           "top1000",
			SkipCDN:                true,
			Fingerprint:            true,
			VulnScan:               true,
			WebCrawler:             true,
			DirScan:                false,
		})

	case models.TaskTypeSubdomain:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   10,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: false,
			PortScan:               false,
		})

	case models.TaskTypeTakeover:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan:          true,
			SubdomainMaxEnumTime:   10,
			SubdomainResolveIP:     true,
			SubdomainCheckTakeover: true,
			PortScan:               false,
		})

	case models.TaskTypePortScan:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "top1000",
			SkipCDN:       true,
			Fingerprint:   true,
		})

	case models.TaskTypeFingerprint:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
		})

	case models.TaskTypeVulnScan:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			VulnScan:      true,
		})

	case models.TaskTypeDirScan:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			DirScan:       true,
		})

	case models.TaskTypeCrawler:
		e.executeStreamingPipeline(task, &PipelineConfig{
			SubdomainScan: false,
			PortScan:      true,
			PortScanMode:  "quick",
			SkipCDN:       true,
			Fingerprint:   true,
			WebCrawler:    true,
		})

	default:
		e.failTask(task, "未知的任务类型: "+string(task.Type))
	}
}

// executeStreamingPipeline 使用 StreamingPipeline 执行任务
func (e *TaskExecutor) executeStreamingPipeline(task *models.Task, config *PipelineConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()

	log.Printf("[TaskExecutor] Starting StreamingPipeline for task %s, type: %s", task.ID.Hex(), task.Type)

	// 创建流水线
	pipeline := NewStreamingPipeline(ctx, task, config)

	// 启动流水线
	if err := pipeline.Start(task.Targets); err != nil {
		e.failTask(task, fmt.Sprintf("流水线启动失败: %v", err))
		return
	}

	// 收集结果
	var resultCount int
	var subdomainCount, portCount, vulnCount, urlCount int

	for result := range pipeline.Results() {
		resultCount++

		// 根据结果类型保存到数据库
		var scanResult *models.ScanResult
		switch r := result.(type) {
		case SubdomainResult:
			subdomainCount++
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeDomain,
				Source:      r.Source,
				Data: bson.M{
					"domain":      r.Domain,
					"root_domain": r.RootDomain,
					"ips":         r.IPs,
					"cnames":      r.CNAMEs,
				},
				CreatedAt: time.Now(),
			}

		case PortAlive:
			if r.Port != "" {
				portCount++
				scanResult = &models.ScanResult{
					TaskID:      task.ID,
					WorkspaceID: task.WorkspaceID,
					Type:        models.ResultTypePort,
					Source:      "rustscan",
					Data: bson.M{
						"host":    r.Host,
						"ip":      r.IP,
						"port":    r.Port,
						"service": r.Service,
					},
					CreatedAt: time.Now(),
				}
			}

		case AssetHttp:
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeService,
				Source:      "fingerprint",
				Data: bson.M{
					"url":          r.URL,
					"host":         r.Host,
					"ip":           r.IP,
					"port":         r.Port,
					"title":        r.Title,
					"status_code":  r.StatusCode,
					"server":       r.Server,
					"technologies": r.Technologies,
					"fingerprints": r.Fingerprints,
				},
				CreatedAt: time.Now(),
			}

		case VulnResult:
			vulnCount++
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeVuln,
				Source:      r.Source,
				Data: bson.M{
					"vuln_id":     r.VulnID,
					"name":        r.Name,
					"target":      r.Target,
					"severity":    r.Severity,
					"description": r.Description,
					"evidence":    r.Evidence,
					"remediation": r.Remediation,
					"reference":   r.Reference,
					"matched_at":  r.MatchedAt,
				},
				CreatedAt: time.Now(),
			}

		case UrlResult:
			urlCount++
			scanResult = &models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeURL,
				Source:      r.Source,
				Data: bson.M{
					"url":    r.Output,
					"input":  r.Input,
					"method": r.Method,
					"source": r.Source,
				},
				CreatedAt: time.Now(),
			}
		}

		// 保存结果
		if scanResult != nil {
			if err := e.resultService.CreateResult(scanResult); err != nil {
				log.Printf("[TaskExecutor] Failed to save result: %v", err)
			}
		}

		// 定期更新进度
		if resultCount%100 == 0 {
			e.updateProgress(task, 50) // 简单的进度更新
		}
	}

	// 任务完成
	log.Printf("[TaskExecutor] Task %s completed: subdomains=%d, ports=%d, vulns=%d, urls=%d",
		task.ID.Hex(), subdomainCount, portCount, vulnCount, urlCount)
	e.completeTask(task, resultCount)
}

// updateProgress 更新任务进度
func (e *TaskExecutor) updateProgress(task *models.Task, progress int) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"progress": progress,
	})
}

// createRootDomainRecords 为目标创建根域名记录（如果不是IP地址）
func (e *TaskExecutor) createRootDomainRecords(task *models.Task) {
	domainResults := make([]models.ScanResult, 0)
	for _, target := range task.Targets {
		if !isIPAddress(target) {
			domainResult := models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeDomain,
				Source:      "user_input",
				Data: bson.M{
					"domain":      target,
					"root_domain": target,
				},
				CreatedAt: time.Now(),
			}
			domainResults = append(domainResults, domainResult)
		}
	}
	if len(domainResults) > 0 {
		e.saveResults(task, domainResults)
		log.Printf("[TaskExecutor] Created %d root domain records", len(domainResults))
	}
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

	// 发送通知
	summary := fmt.Sprintf("扫描任务已完成\n目标: %v\n结果数量: %d", task.Targets, resultCount)
	stats := map[string]interface{}{
		"result_count": resultCount,
		"targets":      task.Targets,
		"type":         task.Type,
	}
	notify.GetGlobalManager().NotifyTaskComplete(task.Name, task.ID.Hex(), true, summary, stats)
}

// failTask 任务失败
func (e *TaskExecutor) failTask(task *models.Task, errMsg string) {
	e.taskService.UpdateTask(task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusFailed,
		"completed_at": time.Now(),
		"error":        errMsg,
	})
	log.Printf("[TaskExecutor] Task %s failed: %s", task.ID.Hex(), errMsg)

	// 发送通知
	summary := fmt.Sprintf("扫描任务失败\n目标: %v\n错误: %s", task.Targets, errMsg)
	stats := map[string]interface{}{
		"error":   errMsg,
		"targets": task.Targets,
		"type":    task.Type,
	}
	notify.GetGlobalManager().NotifyTaskComplete(task.Name, task.ID.Hex(), false, summary, stats)
}

// executorIsIPAddress 判断是否为 IP 地址 (executor专用)
func executorIsIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
