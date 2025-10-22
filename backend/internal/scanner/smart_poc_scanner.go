package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// SmartPoCScanner 智能PoC扫描器 - 基于指纹智能匹配PoC
// 职责：协调指纹匹配和PoC执行流程，不直接处理匹配和执行逻辑
type SmartPoCScanner struct {
	pocMatcher    *PoCMatcher
	executor      *PoCExecutor
	maxConcurrent int // 最大并发数
}

// NewSmartPoCScanner 创建智能PoC扫描器
func NewSmartPoCScanner() *SmartPoCScanner {
	return &SmartPoCScanner{
		pocMatcher:    NewPoCMatcher(),
		executor:      NewPoCExecutor(),
		maxConcurrent: 10, // 默认10个并发
	}
}

// ScanWithFingerprints 基于指纹进行智能PoC扫描
// 流程: 1. 获取站点 → 2. 提取指纹 → 3. 匹配PoC → 4. 并发执行 → 5. 保存结果
func (sps *SmartPoCScanner) ScanWithFingerprints(ctx *ScanContext) error {
	ctx.Logger.Printf("=== Smart PoC Scanner Started ===")

	// 1. 获取所有站点
	var sites []models.Site
	if err := database.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return fmt.Errorf("failed to get sites: %w", err)
	}

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites found for PoC scanning")
		return nil
	}

	ctx.Logger.Printf("Found %d sites for PoC scanning", len(sites))

	// 2. 并发扫描所有站点
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, sps.maxConcurrent)
	totalVulnerabilities := 0
	scannedTargets := make(map[string]bool)

	for _, site := range sites {
		// 检查任务是否被取消
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("PoC scan cancelled by user")
			wg.Wait()
			return ctx.Ctx.Err()
		default:
		}

		// 去重：跳过已扫描的URL
		mu.Lock()
		if scannedTargets[site.URL] {
			mu.Unlock()
			continue
		}
		scannedTargets[site.URL] = true
		mu.Unlock()

		wg.Add(1)
		go func(s models.Site) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 扫描单个站点
			vulns := sps.scanSingleSite(ctx, s)

			// 保存漏洞到数据库
			if len(vulns) > 0 {
				mu.Lock()
				for _, vuln := range vulns {
					if err := database.DB.Create(vuln).Error; err != nil {
						ctx.Logger.Printf("Failed to save vulnerability: %v", err)
					}
				}
				totalVulnerabilities += len(vulns)
				ctx.Logger.Printf("[!] Found %d vulnerabilities on %s", len(vulns), s.URL)
				mu.Unlock()
			}
		}(site)
	}

	wg.Wait()

	ctx.Logger.Printf("=== PoC Scan Complete ===")
	ctx.Logger.Printf("Scanned %d sites, found %d vulnerabilities", len(sites), totalVulnerabilities)

	return nil
}

// scanSingleSite 扫描单个站点（提取为独立方法，便于测试和维护）
func (sps *SmartPoCScanner) scanSingleSite(ctx *ScanContext, site models.Site) []*models.Vulnerability {
	// 1. 提取站点指纹
	fingerprints := extractFingerprints(site)
	if len(fingerprints) == 0 {
		ctx.Logger.Printf("No fingerprints for %s, skipping", site.URL)
		return nil
	}

	ctx.Logger.Printf("Site %s fingerprints: %v", site.URL, fingerprints)

	// 2. 根据指纹匹配PoC
	matchedPoCs, err := sps.pocMatcher.MatchPoCsByFingerprints(fingerprints)
	if err != nil {
		ctx.Logger.Printf("Failed to match PoCs for %s: %v", site.URL, err)
		return nil
	}

	if len(matchedPoCs) == 0 {
		ctx.Logger.Printf("No matching PoCs for %s", site.URL)
		return nil
	}

	ctx.Logger.Printf("Matched %d PoCs for %s", len(matchedPoCs), site.URL)

	// 3. 执行匹配的PoC
	return sps.executeMatchedPoCs(ctx, site.URL, matchedPoCs)
}

// executeMatchedPoCs 执行匹配的PoC列表
func (sps *SmartPoCScanner) executeMatchedPoCs(ctx *ScanContext, target string, pocs []models.PoC) []*models.Vulnerability {
	var vulnerabilities []*models.Vulnerability

	ctx.Logger.Printf("Executing %d PoCs against %s", len(pocs), target)

	for _, poc := range pocs {
		// 检查取消
		select {
		case <-ctx.Ctx.Done():
			return vulnerabilities
		default:
		}

		// 跳过未启用的PoC
		if !poc.IsEnabled {
			continue
		}

		ctx.Logger.Printf("Testing PoC: %s on %s", poc.Name, target)

		// 执行PoC（使用共享的executor实例）
		result, err := sps.executor.Execute(&poc, target)
		if err != nil {
			ctx.Logger.Printf("Failed to execute PoC %s: %v", poc.Name, err)
			continue
		}

		// 发现漏洞
		if result.Vulnerable {
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         target,
				Type:        "poc",
				VulnType:    poc.Category,
				Severity:    poc.Severity,
				Title:       poc.Name,
				Description: fmt.Sprintf("%s\n\nDetails: %s", poc.Description, result.Details),
				Reference:   poc.Reference,
				Source:      "smart_poc",
			}
			vulnerabilities = append(vulnerabilities, vuln)
			ctx.Logger.Printf("[VULN] %s - %s: %s", target, poc.Name, result.Message)
		}
	}

	ctx.Logger.Printf("Completed PoC scan for %s, found %d vulnerabilities", target, len(vulnerabilities))
	return vulnerabilities
}

// extractFingerprints 提取站点指纹（独立函数，不依赖 scanner 实例）
func extractFingerprints(site models.Site) []string {
	var fingerprints []string
	seen := make(map[string]bool)

	// 从多个字段提取指纹
	sources := []string{
		site.Fingerprint,
		site.Server,
	}

	for _, source := range sources {
		if source == "" {
			continue
		}

		// 支持逗号分隔的多个指纹
		parts := splitAndTrim(source)
		for _, part := range parts {
			if part != "" && !seen[part] {
				fingerprints = append(fingerprints, part)
				seen[part] = true
			}
		}
	}
	
	// 从Fingerprints数组字段提取
	for _, fp := range site.Fingerprints {
		if fp != "" && !seen[fp] {
			fingerprints = append(fingerprints, fp)
			seen[fp] = true
		}
	}

	// 从Title提取特定关键词
	if site.Title != "" {
		keywords := []string{"Tomcat", "WebLogic", "JBoss", "WordPress", "Joomla", "Drupal", "phpMyAdmin", "Jenkins"}
		titleLower := strings.ToLower(site.Title)
		for _, keyword := range keywords {
			if strings.Contains(titleLower, strings.ToLower(keyword)) && !seen[keyword] {
				fingerprints = append(fingerprints, keyword)
				seen[keyword] = true
			}
		}
	}

	return fingerprints
}

// splitAndTrim 分割并清理字符串（工具函数）
func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetMatchingPoCsForSite 获取站点匹配的PoC（用于API预览）
func (sps *SmartPoCScanner) GetMatchingPoCsForSite(siteID string) ([]models.PoC, error) {
	var site models.Site
	if err := database.DB.First(&site, "id = ?", siteID).Error; err != nil {
		return nil, err
	}

	fingerprints := extractFingerprints(site)
	return sps.pocMatcher.MatchPoCsByFingerprints(fingerprints)
}
