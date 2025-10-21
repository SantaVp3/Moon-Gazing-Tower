package scanner

import (
	"fmt"
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// SmartPoCScanner 智能PoC扫描器 - 基于指纹匹配
type SmartPoCScanner struct {
	pocMatcher *PoCMatcher
	executor   *PoCExecutor
}

// NewSmartPoCScanner 创建智能PoC扫描器
func NewSmartPoCScanner() *SmartPoCScanner {
	return &SmartPoCScanner{
		pocMatcher: NewPoCMatcher(),
		executor:   NewPoCExecutor(),
	}
}

// ScanWithFingerprints 基于指纹进行智能PoC扫描
// 流程: 1. 获取站点指纹 -> 2. 匹配相关PoC -> 3. 执行匹配的PoC
func (sps *SmartPoCScanner) ScanWithFingerprints(ctx *ScanContext) error {
	ctx.Logger.Printf("Starting smart PoC scan with fingerprint matching...")

	// 1. 获取所有站点及其指纹
	var sites []models.Site
	if err := database.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites).Error; err != nil {
		return fmt.Errorf("failed to get sites: %w", err)
	}

	if len(sites) == 0 {
		ctx.Logger.Printf("No sites found for smart PoC scan")
		return nil
	}

	ctx.Logger.Printf("Found %d sites for smart PoC scanning", len(sites))

	totalVulnerabilities := 0
	scannedTargets := make(map[string]bool) // 避免重复扫描

	// 2. 对每个站点进行智能扫描
	for _, site := range sites {
		// 检查任务是否被取消
		select {
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Smart PoC scan cancelled by user")
			return ctx.Ctx.Err()
		default:
		}

		// 跳过已扫描的URL
		if scannedTargets[site.URL] {
			continue
		}
		scannedTargets[site.URL] = true

		// 解析站点指纹
		fingerprints := sps.extractFingerprints(site)
		if len(fingerprints) == 0 {
			ctx.Logger.Printf("No fingerprints found for %s, skipping", site.URL)
			continue
		}

		ctx.Logger.Printf("Site %s has fingerprints: %v", site.URL, fingerprints)

		// 3. 根据指纹匹配PoC
		matchedPoCs, err := sps.pocMatcher.MatchPoCsByFingerprints(fingerprints)
		if err != nil {
			ctx.Logger.Printf("Failed to match PoCs for %s: %v", site.URL, err)
			continue
		}

		if len(matchedPoCs) == 0 {
			ctx.Logger.Printf("No matching PoCs found for fingerprints: %v", fingerprints)
			continue
		}

		ctx.Logger.Printf("Matched %d PoCs for %s (fingerprints: %v)", 
			len(matchedPoCs), site.URL, fingerprints)

		// 4. 执行匹配的PoC
		vulns := sps.executeMatchedPoCs(ctx, site.URL, matchedPoCs)
		totalVulnerabilities += len(vulns)

		// 保存漏洞到数据库
		for _, vuln := range vulns {
			database.DB.Create(vuln)
		}
	}

	ctx.Logger.Printf("Smart PoC scan completed, found %d vulnerabilities from %d sites", 
		totalVulnerabilities, len(sites))

	return nil
}

// extractFingerprints 从站点中提取指纹信息
func (sps *SmartPoCScanner) extractFingerprints(site models.Site) []string {
	var fingerprints []string

	// 从Fingerprints字段提取(JSON数组)
	if len(site.Fingerprints) > 0 {
		fingerprints = append(fingerprints, site.Fingerprints...)
	}

	// 从Fingerprint字段提取(单个指纹字符串)
	if site.Fingerprint != "" {
		// 可能是逗号分隔的字符串
		parts := strings.Split(site.Fingerprint, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				fingerprints = append(fingerprints, part)
			}
		}
	}

	// 从Server字段提取
	if site.Server != "" {
		fingerprints = append(fingerprints, site.Server)
	}

	// 从title提取(如果包含特定关键词)
	if site.Title != "" {
		// 可以添加更多启发式规则
		keywords := []string{"Tomcat", "WebLogic", "JBoss", "WordPress", "Joomla", "Drupal", "phpMyAdmin"}
		titleLower := strings.ToLower(site.Title)
		for _, keyword := range keywords {
			if strings.Contains(titleLower, strings.ToLower(keyword)) {
				fingerprints = append(fingerprints, keyword)
			}
		}
	}

	// 去重
	fingerprints = sps.uniqueStrings(fingerprints)

	return fingerprints
}

// executeMatchedPoCs 执行匹配的PoC
func (sps *SmartPoCScanner) executeMatchedPoCs(ctx *ScanContext, target string, pocs []models.PoC) []*models.Vulnerability {
	var vulnerabilities []*models.Vulnerability

	ctx.Logger.Printf("Executing %d PoCs against %s", len(pocs), target)

	// 创建PoC执行器
	executor := NewPoCExecutor()

	// 执行每个PoC
	for _, poc := range pocs {
		if !poc.IsEnabled {
			continue
		}

		ctx.Logger.Printf("Testing PoC: %s (%s) against %s", poc.Name, poc.CVE, target)

		result, err := executor.Execute(&poc, target)
		if err != nil {
			ctx.Logger.Printf("Failed to execute PoC %s: %v", poc.Name, err)
			continue
		}

		if result.Vulnerable {
			ctx.Logger.Printf("✓ Vulnerability found: %s - %s", poc.Name, result.Message)
			
			// 创建漏洞记录
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         target,
				Type:        "poc",
				VulnType:    poc.Category,
				Severity:    poc.Severity,
				Title:       poc.Name,
				Description: fmt.Sprintf("%s\n\nCVE: %s\nPoC ID: %s\n\n%s", poc.Description, poc.CVE, poc.ID, result.Details),
				Source:      "smart_poc",
				Reference:   poc.Reference,
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	ctx.Logger.Printf("Completed PoC scan for %s, found %d vulnerabilities", target, len(vulnerabilities))
	return vulnerabilities
}

// uniqueStrings 字符串数组去重
func (sps *SmartPoCScanner) uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range strs {
		str = strings.TrimSpace(str)
		if str == "" {
			continue
		}
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

// GetMatchingPoCsForSite 获取站点匹配的PoC(用于预览)
func (sps *SmartPoCScanner) GetMatchingPoCsForSite(siteID string) ([]models.PoC, error) {
	var site models.Site
	if err := database.DB.First(&site, "id = ?", siteID).Error; err != nil {
		return nil, err
	}

	fingerprints := sps.extractFingerprints(site)
	return sps.pocMatcher.MatchPoCsByFingerprints(fingerprints)
}
