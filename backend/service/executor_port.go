package service

import (
	"context"
	"log"
	"time"

	"moongazing/models"
	"moongazing/scanner/core"
	"moongazing/scanner/portscan"

	"go.mongodb.org/mongo-driver/bson"
)

// executePortScan 执行端口扫描
func (e *TaskExecutor) executePortScan(task *models.Task) {
	log.Printf("[TaskExecutor] Executing port scan for task: %s", task.ID.Hex())

	targets := task.Targets
	if len(targets) == 0 {
		e.failTask(task, "没有目标")
		return
	}

	// 首先为每个非IP目标创建根域名记录

	results := make([]models.ScanResult, 0)

	// 使用 GoGo 进行端口扫描
	gogoConfig := &portscan.GoGoConfig{
		Timeout: task.Config.Timeout,
		Threads: task.Config.Threads,
	}
	if gogoConfig.Timeout <= 0 {
		gogoConfig.Timeout = 30
	}
	if gogoConfig.Threads <= 0 {
		gogoConfig.Threads = 1000
	}

	gogoScanner := portscan.NewGoGoScannerWithConfig(gogoConfig)
	if !gogoScanner.IsAvailable() {
		e.failTask(task, "GoGo 端口扫描器初始化失败")
		return
	}

	log.Printf("[TaskExecutor] Using GoGo for port scanning, config: timeout=%ds, threads=%d",
		gogoConfig.Timeout, gogoConfig.Threads)

	for i, target := range targets {
		progress := int((float64(i) / float64(len(targets))) * 100)
		e.updateProgress(task, progress)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)

		scanResult, err := e.runPortScanMode(ctx, gogoScanner, target, task.Config.PortScanMode, task.Config.PortRange)
		cancel()

		if err != nil {
			log.Printf("[TaskExecutor] GoGo error on %s: %v", target, err)
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

// runPortScanMode 根据模式运行端口扫描
func (e *TaskExecutor) runPortScanMode(ctx context.Context, gogoScanner *portscan.GoGoScanner, target, mode, customPorts string) (*core.ScanResult, error) {
	if mode == "" {
		mode = "quick"
	}

	switch mode {
	case "full":
		log.Printf("[TaskExecutor] Running full port scan (1-65535) on %s", target)
		return gogoScanner.FullScan(ctx, target)
	case "top1000":
		log.Printf("[TaskExecutor] Running top 1000 port scan on %s", target)
		return gogoScanner.Top1000Scan(ctx, target)
	case "custom":
		if customPorts == "" {
			customPorts = "1-1000"
		}
		log.Printf("[TaskExecutor] Running custom port scan (%s) on %s", customPorts, target)
		return gogoScanner.ScanPorts(ctx, target, customPorts)
	default:
		log.Printf("[TaskExecutor] Running quick port scan on %s", target)
		return gogoScanner.QuickScan(ctx, target)
	}
}
