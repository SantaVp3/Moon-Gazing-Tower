package scanner

import (
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// PoCMatcher PoC智能匹配服务
type PoCMatcher struct{}

// NewPoCMatcher 创建PoC匹配器
func NewPoCMatcher() *PoCMatcher {
	return &PoCMatcher{}
}

// MatchPoCsByFingerprints 根据指纹匹配PoC
// fingerprints: 识别到的指纹名称列表
// 返回匹配的PoC列表
func (pm *PoCMatcher) MatchPoCsByFingerprints(fingerprints []string) ([]models.PoC, error) {
	if len(fingerprints) == 0 {
		return []models.PoC{}, nil
	}

	var matchedPoCs []models.PoC
	var allPoCs []models.PoC

	// 获取所有启用的PoC
	if err := database.DB.Where("is_enabled = ?", true).Find(&allPoCs).Error; err != nil {
		return nil, err
	}

	// 对每个PoC进行匹配
	for _, poc := range allPoCs {
		if pm.isPoCMatched(poc, fingerprints) {
			matchedPoCs = append(matchedPoCs, poc)
		}
	}

	return matchedPoCs, nil
}

// isPoCMatched 判断PoC是否匹配指纹
func (pm *PoCMatcher) isPoCMatched(poc models.PoC, fingerprints []string) bool {
	// 如果PoC没有设置指纹关联和应用名称，默认不匹配(避免无差别扫描)
	if poc.Fingerprints == "" && poc.AppNames == "" {
		return false
	}

	matchMode := poc.MatchMode
	if matchMode == "" {
		matchMode = "fuzzy" // 默认模糊匹配
	}

	switch matchMode {
	case "exact":
		return pm.exactMatch(poc, fingerprints)
	case "fuzzy":
		return pm.fuzzyMatch(poc, fingerprints)
	case "keyword":
		return pm.keywordMatch(poc, fingerprints)
	default:
		return pm.fuzzyMatch(poc, fingerprints)
	}
}

// exactMatch 精确匹配 - PoC指纹必须完全匹配
func (pm *PoCMatcher) exactMatch(poc models.PoC, fingerprints []string) bool {
	if poc.Fingerprints == "" {
		return false
	}

	pocFingerprints := pm.splitAndTrim(poc.Fingerprints)
	fingerprintMap := make(map[string]bool)
	for _, fp := range fingerprints {
		fingerprintMap[strings.ToLower(fp)] = true
	}

	// 所有PoC指定的指纹都必须存在
	for _, pocFp := range pocFingerprints {
		if !fingerprintMap[strings.ToLower(pocFp)] {
			return false
		}
	}

	return len(pocFingerprints) > 0
}

// fuzzyMatch 模糊匹配 - 只要有一个指纹匹配即可
func (pm *PoCMatcher) fuzzyMatch(poc models.PoC, fingerprints []string) bool {
	// 检查fingerprints字段
	if poc.Fingerprints != "" {
		pocFingerprints := pm.splitAndTrim(poc.Fingerprints)
		for _, pocFp := range pocFingerprints {
			for _, fp := range fingerprints {
				if pm.fuzzyCompare(pocFp, fp) {
					return true
				}
			}
		}
	}

	// 检查app_names字段
	if poc.AppNames != "" {
		appNames := pm.splitAndTrim(poc.AppNames)
		for _, appName := range appNames {
			for _, fp := range fingerprints {
				if pm.fuzzyCompare(appName, fp) {
					return true
				}
			}
		}
	}

	return false
}

// keywordMatch 关键词匹配 - 包含关键词即匹配
func (pm *PoCMatcher) keywordMatch(poc models.PoC, fingerprints []string) bool {
	// 检查fingerprints字段
	if poc.Fingerprints != "" {
		pocFingerprints := pm.splitAndTrim(poc.Fingerprints)
		for _, pocFp := range pocFingerprints {
			pocFpLower := strings.ToLower(pocFp)
			for _, fp := range fingerprints {
				fpLower := strings.ToLower(fp)
				if strings.Contains(fpLower, pocFpLower) || strings.Contains(pocFpLower, fpLower) {
					return true
				}
			}
		}
	}

	// 检查app_names字段
	if poc.AppNames != "" {
		appNames := pm.splitAndTrim(poc.AppNames)
		for _, appName := range appNames {
			appNameLower := strings.ToLower(appName)
			for _, fp := range fingerprints {
				fpLower := strings.ToLower(fp)
				if strings.Contains(fpLower, appNameLower) || strings.Contains(appNameLower, fpLower) {
					return true
				}
			}
		}
	}

	return false
}

// fuzzyCompare 模糊比较两个字符串
func (pm *PoCMatcher) fuzzyCompare(str1, str2 string) bool {
	s1 := strings.ToLower(strings.TrimSpace(str1))
	s2 := strings.ToLower(strings.TrimSpace(str2))

	// 完全相同
	if s1 == s2 {
		return true
	}

	// 包含关系
	if strings.Contains(s1, s2) || strings.Contains(s2, s1) {
		return true
	}

	// 移除常见分隔符后比较
	s1Clean := pm.cleanString(s1)
	s2Clean := pm.cleanString(s2)
	if s1Clean == s2Clean {
		return true
	}

	return false
}

// cleanString 清理字符串,移除常见分隔符
func (pm *PoCMatcher) cleanString(s string) string {
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ".", "")
	return s
}

// splitAndTrim 分割并去除空白
func (pm *PoCMatcher) splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetMatchedPoCsByAppName 根据应用名称获取匹配的PoC
func (pm *PoCMatcher) GetMatchedPoCsByAppName(appName string) ([]models.PoC, error) {
	var pocs []models.PoC

	// 使用LIKE查询模糊匹配
	query := database.DB.Where("is_enabled = ?", true)
	query = query.Where(
		"app_names LIKE ? OR fingerprints LIKE ? OR name LIKE ?",
		"%"+appName+"%",
		"%"+appName+"%",
		"%"+appName+"%",
	)

	if err := query.Find(&pocs).Error; err != nil {
		return nil, err
	}

	return pocs, nil
}

// GetPoCStats 获取PoC匹配统计
func (pm *PoCMatcher) GetPoCStats(fingerprints []string) map[string]interface{} {
	matchedPoCs, _ := pm.MatchPoCsByFingerprints(fingerprints)

	stats := make(map[string]interface{})
	stats["total_matched"] = len(matchedPoCs)
	stats["matched_fingerprints"] = fingerprints

	// 按严重等级分类
	severityCount := make(map[string]int)
	for _, poc := range matchedPoCs {
		severityCount[poc.Severity]++
	}
	stats["severity_distribution"] = severityCount

	// 按分类统计
	categoryCount := make(map[string]int)
	for _, poc := range matchedPoCs {
		categoryCount[poc.Category]++
	}
	stats["category_distribution"] = categoryCount

	return stats
}
