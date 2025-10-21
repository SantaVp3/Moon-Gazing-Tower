package services

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
)

// FingerprintLoader 指纹加载器
type FingerprintLoader struct{}

// NewFingerprintLoader 创建指纹加载器
func NewFingerprintLoader() *FingerprintLoader {
	return &FingerprintLoader{}
}

// LoadDefaultFingerprints 加载默认指纹库（首次启动时）
func (l *FingerprintLoader) LoadDefaultFingerprints() error {
	// 检查是否已经有指纹数据
	var count int64
	database.DB.Model(&models.Fingerprint{}).Count(&count)
	
	if count > 0 {
		fmt.Printf("数据库中已有 %d 条指纹，跳过自动加载\n", count)
		return nil
	}

	fmt.Println("首次启动，开始加载默认指纹库...")

	// 指纹文件路径
	fingerprintFile := "configs/fingerprints/finger.yaml"
	
	// 检查文件是否存在
	if _, err := os.Stat(fingerprintFile); os.IsNotExist(err) {
		fmt.Printf("警告：默认指纹文件不存在: %s\n", fingerprintFile)
		return nil
	}

	// 读取文件
	file, err := os.Open(fingerprintFile)
	if err != nil {
		return fmt.Errorf("failed to open fingerprint file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read fingerprint file: %v", err)
	}

	// 解析 YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	fmt.Printf("成功解析 YAML，共 %d 个指纹定义\n", len(rawData))

	// 转换并导入指纹
	imported, skipped, failed := l.importFingerprints(rawData)

	fmt.Printf("指纹加载完成！成功: %d, 跳过: %d, 失败: %d\n", imported, skipped, failed)
	
	return nil
}

// importFingerprints 导入指纹数据
func (l *FingerprintLoader) importFingerprints(rawData map[string]interface{}) (imported, skipped, failed int) {
	totalFingerprints := len(rawData)
	processedCount := 0
	
	for name, value := range rawData {
		processedCount++
		if processedCount%1000 == 0 {
			fmt.Printf("处理进度: %d/%d (成功:%d, 跳过:%d, 失败:%d)\n", 
				processedCount, totalFingerprints, imported, skipped, failed)
		}
		
		// 跳过空名称
		if name == "" {
			failed++
			continue
		}

		// 解析规则列表
		rules, ok := value.([]interface{})
		if !ok {
			// 尝试作为单个规则处理
			if ruleStr, ok := value.(string); ok {
				rules = []interface{}{ruleStr}
			} else {
				failed++
				continue
			}
		}

		// 为每个规则创建指纹
		for ruleIdx, rule := range rules {
			ruleStr, ok := rule.(string)
			if !ok {
				failed++
				continue
			}

			// 处理复杂规则：拆分 || 连接的规则
			orRules := l.splitOrRules(ruleStr)
			
			for _, singleRule := range orRules {
				// 解析单个规则
				fingerprint := l.parseRule(name, singleRule)
				if fingerprint == nil {
					// 只在前100次失败时打印详细日志
					if failed < 100 {
						fmt.Printf("  解析失败: %s - 规则: %s\n", name, singleRule)
					}
					failed++
					continue
				}

				// 检查是否已存在（根据名称去重）
				var existing models.Fingerprint
				err := database.DB.Where("name = ?", fingerprint.Name).
					First(&existing).Error

				if err == nil {
					// 已存在，跳过
					skipped++
					continue
				}

				// 批量插入优化：收集到批次后再插入
				if err := database.DB.Create(fingerprint).Error; err != nil {
					// 忽略重复键错误
					if !strings.Contains(err.Error(), "duplicate") && 
					   !strings.Contains(err.Error(), "unique constraint") {
						fmt.Printf("插入指纹失败: %s [规则%d] - %v\n", name, ruleIdx+1, err)
					}
					failed++
					continue
				}

				imported++
			}
		}
	}

	return
}

// splitOrRules 拆分 || 连接的规则
func (l *FingerprintLoader) splitOrRules(rule string) []string {
	// 简单拆分：按 || 分割，但要注意引号内的内容
	// 为简化实现，我们只在引号外进行拆分
	
	var results []string
	var current strings.Builder
	inQuotes := false
	escapeNext := false
	
	runes := []rune(rule)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		
		if escapeNext {
			current.WriteRune(r)
			escapeNext = false
			continue
		}
		
		if r == '\\' {
			current.WriteRune(r)
			escapeNext = true
			continue
		}
		
		if r == '"' || r == '\'' {
			current.WriteRune(r)
			inQuotes = !inQuotes
			continue
		}
		
		// 检测 ||
		if !inQuotes && r == '|' && i+1 < len(runes) && runes[i+1] == '|' {
			// 找到分隔符
			trimmed := strings.TrimSpace(current.String())
			if trimmed != "" {
				results = append(results, trimmed)
			}
			current.Reset()
			i++ // 跳过第二个 |
			continue
		}
		
		current.WriteRune(r)
	}
	
	// 添加最后一部分
	trimmed := strings.TrimSpace(current.String())
	if trimmed != "" {
		results = append(results, trimmed)
	}
	
	// 如果没有找到分隔符，返回原规则
	if len(results) == 0 {
		return []string{rule}
	}
	
	return results
}

// parseRule 解析指纹规则
func (l *FingerprintLoader) parseRule(name, rule string) *models.Fingerprint {
	// 清理规则字符串
	rule = strings.TrimSpace(rule)
	
	// 确定规则类型和内容
	ruleType, method, keywords := l.extractRuleInfo(rule)
	
	if ruleType == "" || len(keywords) == 0 {
		return nil
	}

	// 构建规则内容（JSON格式）
	keywordsJSON, err := json.Marshal(keywords)
	if err != nil {
		return nil
	}
	ruleContent := fmt.Sprintf("%s:%s", method, string(keywordsJSON))

	return &models.Fingerprint{
		Name:        name,
		Category:    "Web", // 默认分类
		RuleType:    ruleType,
		RuleContent: ruleContent,
		Confidence:  80, // 默认可信度
		Description: fmt.Sprintf("Auto-imported from default fingerprint library"),
		IsEnabled:   true,
	}
}

// extractRuleInfo 提取规则信息
func (l *FingerprintLoader) extractRuleInfo(rule string) (ruleType, method string, keywords []string) {
	// 移除首尾的引号（如果有）
	rule = strings.Trim(rule, "'\"")
	
	// 优先级顺序：body > title > header > banner > cert > protocol
	// 这样可以确保优先使用最特征明显的规则类型
	
	priorityPatterns := []struct {
		name    string
		pattern *regexp.Regexp
		ruleType string
	}{
		{"title", regexp.MustCompile(`title\s*==?\s*"([^"]+)"`), "title"},
		{"body", regexp.MustCompile(`body\s*[=~]\s*"([^"]+)"`), "body"},
		{"header", regexp.MustCompile(`header\s*=\s*"([^"]+)"`), "header"},
		{"banner", regexp.MustCompile(`banner\s*[=!~]\s*"([^"]+)"`), "header"},
		{"cert", regexp.MustCompile(`cert\s*=\s*"([^"]+)"`), "header"},
		{"protocol", regexp.MustCompile(`protocol\s*=\s*"([^"]+)"`), "header"},
		{"status", regexp.MustCompile(`status\s*=\s*"([^"]+)"`), "header"},
	}

	// 尝试按优先级匹配
	for _, p := range priorityPatterns {
		matches := p.pattern.FindAllStringSubmatch(rule, -1)
		if len(matches) > 0 {
			// 找到匹配
			for _, match := range matches {
				if len(match) > 1 && match[1] != "" {
					// 清理关键词中的转义字符
					keyword := strings.ReplaceAll(match[1], `\"`, `"`)
					keyword = strings.ReplaceAll(keyword, `\'`, `'`)
					keywords = append(keywords, keyword)
				}
			}
			
			if len(keywords) > 0 {
				ruleType = p.ruleType
				method = "keyword"
				return
			}
		}
	}

	// 如果没有找到标准模式，尝试提取任何带引号的内容作为关键词
	if len(keywords) == 0 {
		simplePattern := regexp.MustCompile(`"([^"]{3,})"`)
		matches := simplePattern.FindAllStringSubmatch(rule, -1)
		if len(matches) > 0 && len(matches[0]) > 1 {
			keywords = append(keywords, matches[0][1])
			ruleType = "body" // 默认为 body
			method = "keyword"
		}
	}

	return
}

// LoadFingerprintsFromFile 从文件加载指纹（供API使用）
func (l *FingerprintLoader) LoadFingerprintsFromFile(filePath string) (imported, skipped, failed int, err error) {
	// 检查文件扩展名
	ext := strings.ToLower(filepath.Ext(filePath))
	
	if ext != ".yaml" && ext != ".yml" {
		return 0, 0, 0, fmt.Errorf("unsupported file format: %s", ext)
	}

	// 读取文件
	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read file: %v", err)
	}

	// 解析 YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to parse YAML: %v", err)
	}

	// 导入指纹
	imported, skipped, failed = l.importFingerprints(rawData)
	
	return imported, skipped, failed, nil
}

