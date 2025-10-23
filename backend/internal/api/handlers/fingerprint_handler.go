package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// FingerprintHandler 指纹处理器
type FingerprintHandler struct{}

// NewFingerprintHandler 创建指纹处理器
func NewFingerprintHandler() *FingerprintHandler {
	return &FingerprintHandler{}
}

// CreateFingerprintRequest 创建指纹请求
type CreateFingerprintRequest struct {
	Name        string   `json:"name" binding:"required"`
	Category    string   `json:"category" binding:"required"`
	DSL         []string `json:"dsl" binding:"required"`
	Description string   `json:"description"`
}

// ListFingerprints 列出所有指纹
func (h *FingerprintHandler) ListFingerprints(c *gin.Context) {
	category := c.Query("category")
	name := c.Query("name")

	// 分页参数
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 20
	}

	query := database.DB.Model(&models.Fingerprint{})

	if category != "" {
		query = query.Where("category = ?", category)
	}
	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}

	var total int64
	query.Count(&total)

	var fingerprints []models.Fingerprint
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("category ASC, name ASC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&fingerprints).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch fingerprints"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"fingerprints": fingerprints,
		"total":        total,
		"page":         pageInt,
		"page_size":    pageSizeInt,
		"total_pages":  totalPages,
	})
}

// GetFingerprint 获取单个指纹
func (h *FingerprintHandler) GetFingerprint(c *gin.Context) {
	id := c.Param("id")

	var fingerprint models.Fingerprint
	if err := database.DB.First(&fingerprint, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Fingerprint not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fingerprint"})
		return
	}

	c.JSON(http.StatusOK, fingerprint)
}

// CreateFingerprint 创建指纹
func (h *FingerprintHandler) CreateFingerprint(c *gin.Context) {
	var req CreateFingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证 DSL 规则
	if len(req.DSL) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DSL rules cannot be empty"})
		return
	}

	fingerprint := &models.Fingerprint{
		Name:        req.Name,
		Category:    req.Category,
		DSL:         req.DSL,
		Description: req.Description,
		IsEnabled:   true,
	}

	if err := database.DB.Create(fingerprint).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create fingerprint"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":     "Fingerprint created successfully",
		"fingerprint": fingerprint,
	})
}

// UpdateFingerprint 更新指纹
func (h *FingerprintHandler) UpdateFingerprint(c *gin.Context) {
	id := c.Param("id")

	var fingerprint models.Fingerprint
	if err := database.DB.First(&fingerprint, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Fingerprint not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get fingerprint"})
		return
	}

	var req CreateFingerprintRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证 DSL 规则
	if len(req.DSL) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DSL rules cannot be empty"})
		return
	}

	// 更新字段
	fingerprint.Name = req.Name
	fingerprint.Category = req.Category
	fingerprint.DSL = req.DSL
	fingerprint.Description = req.Description

	if err := database.DB.Save(&fingerprint).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update fingerprint"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Fingerprint updated successfully",
		"fingerprint": fingerprint,
	})
}

// DeleteFingerprint 删除指纹
func (h *FingerprintHandler) DeleteFingerprint(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.Fingerprint{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete fingerprint"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Fingerprint deleted successfully"})
}

// BatchCreateFingerprints 批量创建指纹
func (h *FingerprintHandler) BatchCreateFingerprints(c *gin.Context) {
	var fingerprints []CreateFingerprintRequest
	if err := c.ShouldBindJSON(&fingerprints); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var created []models.Fingerprint
	for _, req := range fingerprints {
		fp := models.Fingerprint{
			Name:        req.Name,
			Category:    req.Category,
			DSL:         req.DSL,
			Description: req.Description,
			IsEnabled:   true,
		}
		created = append(created, fp)
	}

	if err := database.DB.Create(&created).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create fingerprints"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Fingerprints created successfully",
		"count":   len(created),
	})
}

// GetCategories 获取所有分类
func (h *FingerprintHandler) GetCategories(c *gin.Context) {
	var categories []string
	database.DB.Model(&models.Fingerprint{}).
		Distinct("category").
		Pluck("category", &categories)

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

// FingerprintImportItem 指纹导入项目格式 (支持JSON和YAML)
type FingerprintImportItem struct {
	CMS      string   `json:"cms" yaml:"cms"`
	Method   string   `json:"method" yaml:"method"`
	Location string   `json:"location" yaml:"location"`
	Keyword  []string `json:"keyword" yaml:"keyword"`
}

// UniversalFingerprintFormat 通用指纹格式（自动解析多种格式）
type UniversalFingerprintFormat struct {
	// 通用字段
	Name        string      `yaml:"name" json:"name"`
	ID          string      `yaml:"id" json:"id"`
	CMS         string      `yaml:"cms" json:"cms"`
	Category    string      `yaml:"category" json:"category"`
	Tags        interface{} `yaml:"tags" json:"tags"` // 可能是字符串或数组
	Description string      `yaml:"description" json:"description"`

	// Nuclei风格
	Info     map[string]interface{}   `yaml:"info" json:"info"`
	Matchers []map[string]interface{} `yaml:"matchers" json:"matchers"`

	// EHole/简化风格
	Method   string   `yaml:"method" json:"method"`
	Location string   `yaml:"location" json:"location"`
	Keyword  []string `yaml:"keyword" json:"keyword"`

	// 自定义patterns格式
	Patterns map[string]interface{} `yaml:"patterns" json:"patterns"`

	// ObserverWard风格
	Priority   int                      `yaml:"priority" json:"priority"`
	MatchRules []map[string]interface{} `yaml:"match_rules" json:"match_rules"`

	// Wappalyzer风格（键值对格式）
	Cats    interface{}            `yaml:"cats" json:"cats"`
	HTML    interface{}            `yaml:"html" json:"html"`
	Headers map[string]interface{} `yaml:"headers" json:"headers"`
	Implies interface{}            `yaml:"implies" json:"implies"`

	// 原始数据（用于处理未知格式）
	Raw map[string]interface{} `yaml:",inline" json:"-"`
}

// ImportFingerprints 导入指纹 (支持多种YAML/JSON格式 - 智能识别)
func (h *FingerprintHandler) ImportFingerprints(c *gin.Context) {
	// 调用通用导入接口
	h.ImportFingerprintsUniversal(c)
}

// ImportFingerprintsLegacy 导入指纹 (旧版格式 - 仅用于向后兼容)
func (h *FingerprintHandler) ImportFingerprintsLegacy(c *gin.Context) {
	// 读取原始数据
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body: " + err.Error()})
		return
	}

	// 检测是否为 YAML 格式
	contentType := c.GetHeader("Content-Type")
	isYAML := strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml")

	// 如果 Content-Type 不明确，尝试通过内容判断
	if !isYAML && len(body) > 0 {
		// YAML 通常包含 ":" 作为键值分隔符，且第一行不是 "[" 或 "{"
		bodyStr := strings.TrimSpace(string(body))
		if !strings.HasPrefix(bodyStr, "[") && !strings.HasPrefix(bodyStr, "{") {
			isYAML = true
		}
	}

	var items []FingerprintImportItem

	if isYAML {
		fmt.Println("检测到 YAML 格式，开始解析...")
		if err := yaml.Unmarshal(body, &items); err != nil {
			fmt.Printf("YAML解析错误: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid YAML format: " + err.Error()})
			return
		}
	} else {
		fmt.Println("检测到 JSON 格式，开始解析...")
		if err := json.Unmarshal(body, &items); err != nil {
			fmt.Printf("JSON解析错误: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: " + err.Error()})
			return
		}
	}

	fmt.Printf("接收到 %d 条指纹数据 (格式: %s)\n", len(items), map[bool]string{true: "YAML", false: "JSON"}[isYAML])

	var created []models.Fingerprint
	var failed int
	var skipped int
	var failedReasons []string

	for i, item := range items {
		fmt.Printf("处理第 %d 条: CMS=%s, Method=%s, Location=%s, Keywords=%v\n",
			i+1, item.CMS, item.Method, item.Location, item.Keyword)

		// 验证必填字段
		if item.CMS == "" || item.Method == "" || item.Location == "" || len(item.Keyword) == 0 {
			reason := fmt.Sprintf("第%d条：缺少必填字段 (cms=%s, method=%s, location=%s, keywords=%d个)",
				i+1, item.CMS, item.Method, item.Location, len(item.Keyword))
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> 跳过: %s\n", reason)
			failed++
			continue
		}

		// 转换 location 为 rule_type
		ruleType := convertLocationToRuleType(item.Location)
		if ruleType == "" {
			reason := fmt.Sprintf("第%d条：不支持的location类型 '%s'", i+1, item.Location)
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> 跳过: %s\n", reason)
			failed++
			continue
		}

		// 将关键词转换为 DSL 规则
		dslRules := []string{}
		for _, keyword := range item.Keyword {
			// 根据不同的 location 创建相应的 DSL 规则
			var target string
			switch item.Location {
			case "body":
				target = "body"
			case "title":
				target = "title"
			case "header", "server", "banner":
				target = "header"
			default:
				target = "body"
			}
			// 创建 contains 规则
			dslRule := fmt.Sprintf("contains(%s, '%s')", target, strings.ReplaceAll(keyword, "'", "\\'"))
			dslRules = append(dslRules, dslRule)
		}

		if len(dslRules) == 0 {
			reason := fmt.Sprintf("第%d条：DSL规则为空", i+1)
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> 跳过: %s\n", reason)
			failed++
			continue
		}

		// 检查是否已存在相同的指纹（根据名称去重）
		var existingFingerprint models.Fingerprint
		if err := database.DB.Where("name = ?", item.CMS).First(&existingFingerprint).Error; err == nil {
			// 已存在，跳过
			fmt.Printf("  -> 跳过（已存在）: %s\n", item.CMS)
			skipped++
			continue
		}

		fingerprint := models.Fingerprint{
			Name:        item.CMS,
			Category:    "Web", // 默认分类
			DSL:         dslRules,
			Description: fmt.Sprintf("Imported from JSON - Method: %s, Location: %s", item.Method, item.Location),
			IsEnabled:   true,
		}

		fmt.Printf("  -> 成功创建指纹: %s (DSL规则数: %d)\n", fingerprint.Name, len(fingerprint.DSL))
		created = append(created, fingerprint)
	}

	// 分批插入，使用FirstOrCreate避免重复错误
	successCount := 0
	duplicateCount := 0

	if len(created) > 0 {
		for i, fingerprint := range created {
			// 使用FirstOrCreate来避免重复（根据名称）
			var existing models.Fingerprint
			result := database.DB.Where("name = ?", fingerprint.Name).
				FirstOrCreate(&existing, &fingerprint)

			if result.Error != nil {
				fmt.Printf("第 %d 条保存失败: %v\n", i+1, result.Error)
				failed++
				continue
			}

			if result.RowsAffected > 0 {
				// 新创建的记录
				successCount++
				if (i+1)%100 == 0 {
					fmt.Printf("进度: %d/%d (成功: %d, 重复: %d)\n", i+1, len(created), successCount, duplicateCount)
				}
			} else {
				// 已存在的记录
				duplicateCount++
			}
		}

		fmt.Printf("全部完成：新增 %d 条，跳过重复 %d 条\n", successCount, duplicateCount)
	}

	response := gin.H{
		"message":        "Fingerprints imported successfully",
		"imported_count": successCount,
		"skipped_count":  skipped + duplicateCount,
		"failed_count":   failed,
		"total":          len(items),
	}

	if len(failedReasons) > 0 {
		response["failed_reasons"] = failedReasons
	}

	c.JSON(http.StatusCreated, response)
}

// convertLocationToRuleType 将location转换为rule_type
func convertLocationToRuleType(location string) string {
	location = strings.ToLower(location)
	switch location {
	case "body":
		return "body"
	case "header":
		return "header"
	case "title":
		return "title"
	case "favicon":
		return "favicon"
	case "url":
		return "url"
	default:
		return ""
	}
}

// parseUniversalFingerprint 智能解析通用指纹格式
func parseUniversalFingerprint(item *UniversalFingerprintFormat, index int) (*models.Fingerprint, error) {
	var name, category, description string
	var dslRules []string

	// 1. 提取名称（优先级：name > id > cms）
	if item.Name != "" {
		name = item.Name
	} else if item.ID != "" {
		name = item.ID
	} else if item.CMS != "" {
		name = item.CMS
	}

	if name == "" {
		return nil, fmt.Errorf("指纹缺少名称字段")
	}

	// 2. 提取分类
	category = "Web" // 默认分类
	if item.Category != "" {
		category = item.Category
	} else if item.Info != nil {
		if cat, ok := item.Info["category"].(string); ok {
			category = cat
		} else if tags, ok := item.Info["tags"].(string); ok {
			category = tags
		}
	} else if item.Tags != nil {
		if tagStr, ok := item.Tags.(string); ok {
			category = tagStr
		} else if tagArr, ok := item.Tags.([]interface{}); ok && len(tagArr) > 0 {
			if firstTag, ok := tagArr[0].(string); ok {
				category = firstTag
			}
		}
	}

	// 3. 提取描述
	description = item.Description
	if description == "" && item.Info != nil {
		if desc, ok := item.Info["description"].(string); ok {
			description = desc
		}
	}

	// 4. 根据不同格式提取匹配规则

	// 格式1: Nuclei风格 (matchers)
	if len(item.Matchers) > 0 {
		fmt.Printf("  [格式识别] Nuclei风格\n")
		for _, matcher := range item.Matchers {
			matcherType, _ := matcher["type"].(string)
			part, _ := matcher["part"].(string)
			if part == "" {
				part = "body"
			}

			// 提取关键词
			var words []string
			if wordList, ok := matcher["words"].([]interface{}); ok {
				for _, w := range wordList {
					if ws, ok := w.(string); ok {
						words = append(words, ws)
					}
				}
			} else if word, ok := matcher["word"].(string); ok {
				words = append(words, word)
			}

			// 生成DSL规则
			for _, word := range words {
				dsl := generateDSLRule(part, matcherType, word)
				if dsl != "" {
					dslRules = append(dslRules, dsl)
				}
			}
		}
	}

	// 格式2: EHole风格 (method + location + keyword)
	if len(dslRules) == 0 && len(item.Keyword) > 0 {
		fmt.Printf("  [格式识别] EHole风格\n")
		location := item.Location
		if location == "" {
			location = "body"
		}
		for _, keyword := range item.Keyword {
			dsl := generateDSLRule(location, "keyword", keyword)
			if dsl != "" {
				dslRules = append(dslRules, dsl)
			}
		}
	}

	// 格式3: 自定义patterns格式
	if len(dslRules) == 0 && item.Patterns != nil {
		fmt.Printf("  [格式识别] Patterns风格\n")
		for location, patterns := range item.Patterns {
			if patternList, ok := patterns.([]interface{}); ok {
				for _, p := range patternList {
					if pattern, ok := p.(string); ok {
						dsl := generateDSLRule(location, "keyword", pattern)
						if dsl != "" {
							dslRules = append(dslRules, dsl)
						}
					}
				}
			} else if patternStr, ok := patterns.(string); ok {
				dsl := generateDSLRule(location, "keyword", patternStr)
				if dsl != "" {
					dslRules = append(dslRules, dsl)
				}
			}
		}
	}

	// 格式4: ObserverWard风格 (match_rules)
	if len(dslRules) == 0 && len(item.MatchRules) > 0 {
		fmt.Printf("  [格式识别] ObserverWard风格\n")
		for _, rule := range item.MatchRules {
			// url_path
			if urlPath, ok := rule["url_path"].(string); ok {
				dsl := fmt.Sprintf("contains(url, '%s')", strings.ReplaceAll(urlPath, "'", "\\'"))
				dslRules = append(dslRules, dsl)
			}
			// response_body
			if respBody, ok := rule["response_body"].(string); ok {
				dsl := fmt.Sprintf("contains(body, '%s')", strings.ReplaceAll(respBody, "'", "\\'"))
				dslRules = append(dslRules, dsl)
			}
			// response_header
			if respHeader, ok := rule["response_header"].(string); ok {
				dsl := fmt.Sprintf("contains(header, '%s')", strings.ReplaceAll(respHeader, "'", "\\'"))
				dslRules = append(dslRules, dsl)
			}
			// status_code
			if statusCode, ok := rule["status_code"].(int); ok {
				dsl := fmt.Sprintf("status_code == %d", statusCode)
				dslRules = append(dslRules, dsl)
			}
		}
	}

	// 格式5: Wappalyzer风格 (html, headers)
	if len(dslRules) == 0 && (item.HTML != nil || item.Headers != nil) {
		fmt.Printf("  [格式识别] Wappalyzer风格\n")
		// 处理HTML模式
		if item.HTML != nil {
			if htmlList, ok := item.HTML.([]interface{}); ok {
				for _, h := range htmlList {
					if htmlStr, ok := h.(string); ok {
						dsl := generateDSLRule("body", "keyword", htmlStr)
						if dsl != "" {
							dslRules = append(dslRules, dsl)
						}
					}
				}
			} else if htmlStr, ok := item.HTML.(string); ok {
				dsl := generateDSLRule("body", "keyword", htmlStr)
				if dsl != "" {
					dslRules = append(dslRules, dsl)
				}
			}
		}
		// 处理Headers
		if item.Headers != nil {
			for headerName, headerValue := range item.Headers {
				if hvStr, ok := headerValue.(string); ok {
					dsl := fmt.Sprintf("contains(header, '%s: %s')", headerName, strings.ReplaceAll(hvStr, "'", "\\'"))
					dslRules = append(dslRules, dsl)
				}
			}
		}
	}

	// 如果没有提取到任何规则
	if len(dslRules) == 0 {
		return nil, fmt.Errorf("无法从指纹中提取匹配规则")
	}

	// 生成描述
	if description == "" {
		description = fmt.Sprintf("自动导入的指纹 - 规则数: %d", len(dslRules))
	}

	fingerprint := &models.Fingerprint{
		Name:        name,
		Category:    category,
		DSL:         dslRules,
		Description: description,
		IsEnabled:   true,
	}

	return fingerprint, nil
}

// generateDSLRule 生成DSL规则
func generateDSLRule(location, matchType, pattern string) string {
	location = strings.ToLower(location)

	// 转换location为DSL目标
	var target string
	switch location {
	case "body", "response_body", "html":
		target = "body"
	case "header", "headers", "response_header", "banner", "server":
		target = "header"
	case "title":
		target = "title"
	case "url", "path", "url_path":
		target = "url"
	case "favicon", "icon":
		target = "favicon"
	default:
		target = "body"
	}

	// 转义单引号
	escapedPattern := strings.ReplaceAll(pattern, "'", "\\'")

	// 根据匹配类型生成规则
	switch strings.ToLower(matchType) {
	case "word", "keyword", "contains":
		return fmt.Sprintf("contains(%s, '%s')", target, escapedPattern)
	case "regex", "regexp":
		return fmt.Sprintf("regex(%s, '%s')", target, escapedPattern)
	case "exact", "equals":
		return fmt.Sprintf("%s == '%s'", target, escapedPattern)
	default:
		// 默认使用contains
		return fmt.Sprintf("contains(%s, '%s')", target, escapedPattern)
	}
}

// ImportFingerprintsUniversal 通用指纹导入接口（智能识别多种格式）
func (h *FingerprintHandler) ImportFingerprintsUniversal(c *gin.Context) {
	// 读取原始数据
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body: " + err.Error()})
		return
	}

	// 检测是否为YAML格式
	contentType := c.GetHeader("Content-Type")
	isYAML := strings.Contains(contentType, "yaml") || strings.Contains(contentType, "yml")

	if !isYAML && len(body) > 0 {
		bodyStr := strings.TrimSpace(string(body))
		if !strings.HasPrefix(bodyStr, "[") && !strings.HasPrefix(bodyStr, "{") {
			isYAML = true
		}
	}

	fmt.Printf("📦 开始导入指纹（格式: %s）\n", map[bool]string{true: "YAML", false: "JSON"}[isYAML])

	// 尝试解析为通用格式数组
	var items []UniversalFingerprintFormat

	if isYAML {
		// 先尝试作为数组解析
		if err := yaml.Unmarshal(body, &items); err != nil {
			// 如果失败，尝试作为单个对象解析
			var singleItem UniversalFingerprintFormat
			if err := yaml.Unmarshal(body, &singleItem); err != nil {
				// 如果还是失败，尝试作为map[string]UniversalFingerprintFormat解析（Wappalyzer风格）
				var itemsMap map[string]UniversalFingerprintFormat
				if err := yaml.Unmarshal(body, &itemsMap); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid YAML format: " + err.Error()})
					return
				}
				// 转换map为数组
				for name, item := range itemsMap {
					if item.Name == "" {
						item.Name = name
					}
					items = append(items, item)
				}
			} else {
				items = append(items, singleItem)
			}
		}
	} else {
		// JSON解析
		if err := json.Unmarshal(body, &items); err != nil {
			// 尝试单个对象
			var singleItem UniversalFingerprintFormat
			if err := json.Unmarshal(body, &singleItem); err != nil {
				// 尝试map格式
				var itemsMap map[string]UniversalFingerprintFormat
				if err := json.Unmarshal(body, &itemsMap); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: " + err.Error()})
					return
				}
				for name, item := range itemsMap {
					if item.Name == "" {
						item.Name = name
					}
					items = append(items, item)
				}
			} else {
				items = append(items, singleItem)
			}
		}
	}

	fmt.Printf("✅ 解析成功，共 %d 条指纹\n", len(items))

	var created []models.Fingerprint
	var skipped int
	var failed int
	var failedReasons []string

	for i, item := range items {
		fmt.Printf("\n[%d/%d] 处理指纹...\n", i+1, len(items))

		// 智能解析
		fingerprint, err := parseUniversalFingerprint(&item, i)
		if err != nil {
			reason := fmt.Sprintf("第%d条: %s", i+1, err.Error())
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  ❌ %s\n", reason)
			failed++
			continue
		}

		// 检查是否已存在
		var existing models.Fingerprint
		if err := database.DB.Where("name = ?", fingerprint.Name).First(&existing).Error; err == nil {
			fmt.Printf("  ⏭️ 跳过（已存在）: %s\n", fingerprint.Name)
			skipped++
			continue
		}

		fmt.Printf("  ✅ %s (分类: %s, 规则数: %d)\n", fingerprint.Name, fingerprint.Category, len(fingerprint.DSL))
		created = append(created, *fingerprint)
	}

	// 批量插入
	successCount := 0
	if len(created) > 0 {
		batchSize := 100
		for i := 0; i < len(created); i += batchSize {
			end := i + batchSize
			if end > len(created) {
				end = len(created)
			}
			batch := created[i:end]

			if err := database.DB.Create(&batch).Error; err != nil {
				fmt.Printf("❌ 批量插入失败 (batch %d-%d): %v\n", i, end, err)
				failed += len(batch)
			} else {
				successCount += len(batch)
				fmt.Printf("✅ 批量插入成功 (batch %d-%d)\n", i, end)
			}
		}
	}

	response := gin.H{
		"message":        "Fingerprints imported successfully",
		"imported_count": successCount,
		"skipped_count":  skipped,
		"failed_count":   failed,
		"total":          len(items),
	}

	if len(failedReasons) > 0 && len(failedReasons) <= 10 {
		response["failed_reasons"] = failedReasons
	} else if len(failedReasons) > 10 {
		response["failed_reasons"] = append(failedReasons[:10], fmt.Sprintf("... 还有 %d 个失败", len(failedReasons)-10))
	}

	c.JSON(http.StatusCreated, response)
}
