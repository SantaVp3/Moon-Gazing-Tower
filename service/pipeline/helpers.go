package pipeline

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"moongazing/models"
	"moongazing/service/notify"

	"go.mongodb.org/mongo-driver/bson"
)

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
	stats := bson.M{
		"total_results":         p.totalResults,
		"discovered_assets":     len(p.discoveredAssets),
		"discovered_ports":      len(p.discoveredPorts),
		"discovered_urls":       len(p.discoveredURLs),
		"discovered_subdomains": len(p.discoveredSubdomains),
	}

	p.taskService.UpdateTask(p.task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusCompleted,
		"progress":     100,
		"completed_at": time.Now(),
		"result_stats": stats,
	})

	log.Printf("[Pipeline] Task %s completed with %d results", p.task.ID.Hex(), p.totalResults)

	// 发送通知
	summary := fmt.Sprintf("全量扫描任务已完成\n目标: %v\n子域名: %d\n端口: %d\nURL: %d\n总结果: %d",
		p.task.Targets,
		len(p.discoveredSubdomains),
		len(p.discoveredPorts),
		len(p.discoveredURLs),
		p.totalResults,
	)
	notifyStats := map[string]interface{}{
		"total_results":         p.totalResults,
		"discovered_assets":     len(p.discoveredAssets),
		"discovered_ports":      len(p.discoveredPorts),
		"discovered_urls":       len(p.discoveredURLs),
		"discovered_subdomains": len(p.discoveredSubdomains),
		"targets":               p.task.Targets,
	}
	notify.GetGlobalManager().NotifyTaskComplete(p.task.Name, p.task.ID.Hex(), true, summary, notifyStats)
}

// failTask 任务失败
func (p *ScanPipeline) failTask(errMsg string) {
	p.taskService.UpdateTask(p.task.ID.Hex(), map[string]interface{}{
		"status":       models.TaskStatusFailed,
		"completed_at": time.Now(),
		"last_error":   errMsg,
	})

	log.Printf("[Pipeline] Task %s failed: %s", p.task.ID.Hex(), errMsg)

	// 发送通知
	summary := fmt.Sprintf("全量扫描任务失败\n目标: %v\n错误: %s", p.task.Targets, errMsg)
	stats := map[string]interface{}{
		"error":   errMsg,
		"targets": p.task.Targets,
	}
	notify.GetGlobalManager().NotifyTaskComplete(p.task.Name, p.task.ID.Hex(), false, summary, stats)
}

// 辅助函数

// isIPAddress 判断是否为 IP 地址
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
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
