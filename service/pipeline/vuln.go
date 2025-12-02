package pipeline

import (
	"context"
	"log"
	"time"

	"moongazing/models"
	"moongazing/scanner/vulnscan"
	"go.mongodb.org/mongo-driver/bson"
)

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

// saveVulnResult 保存漏洞扫描结果
func (p *ScanPipeline) saveVulnResult(vuln vulnscan.VulnResult, target string) {
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
