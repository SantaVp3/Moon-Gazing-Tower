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
	
	// 使用 RustScan 进行端口扫描
	rustConfig := &portscan.RustScanConfig{
		Timeout:   task.Config.Timeout,
		BatchSize: task.Config.Threads,
		RateLimit: task.Config.PortScanRate,
	}
	if rustConfig.Timeout <= 0 {
		rustConfig.Timeout = 30
	}
	if rustConfig.BatchSize <= 0 {
		rustConfig.BatchSize = 4500
	}
	
	rustScanner := portscan.NewRustScanScannerWithConfig(rustConfig)
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
		
		scanResult, err := e.runPortScanMode(ctx, rustScanner, target, task.Config.PortScanMode, task.Config.PortRange)
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

// runPortScanMode 根据模式运行端口扫描
func (e *TaskExecutor) runPortScanMode(ctx context.Context, rustScanner *portscan.RustScanScanner, target, mode, customPorts string) (*core.ScanResult, error) {
	if mode == "" {
		mode = "quick"
	}
	
	switch mode {
	case "full":
		log.Printf("[TaskExecutor] Running full port scan (1-65535) on %s", target)
		return rustScanner.FullScan(ctx, target)
	case "top1000":
		log.Printf("[TaskExecutor] Running top 1000 port scan on %s", target)
		return rustScanner.Top1000Scan(ctx, target)
	case "custom":
		if customPorts == "" {
			customPorts = "1-1000"
		}
		log.Printf("[TaskExecutor] Running custom port scan (%s) on %s", customPorts, target)
		return rustScanner.ScanPorts(ctx, target, customPorts)
	default:
		log.Printf("[TaskExecutor] Running quick port scan on %s", target)
		return rustScanner.QuickScan(ctx, target)
	}
}
