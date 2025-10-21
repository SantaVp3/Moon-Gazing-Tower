package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/gin-gonic/gin"
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
	Name        string `json:"name" binding:"required"`
	Category    string `json:"category" binding:"required"`
	RuleType    string `json:"rule_type" binding:"required"`
	RuleContent string `json:"rule_content" binding:"required"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
}

// ListFingerprints 列出所有指纹
func (h *FingerprintHandler) ListFingerprints(c *gin.Context) {
	category := c.Query("category")
	ruleType := c.Query("rule_type")
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
	if ruleType != "" {
		query = query.Where("rule_type = ?", ruleType)
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

	// 验证规则类型
	validRuleTypes := map[string]bool{
		"body": true, "header": true, "title": true, "favicon": true, "url": true,
	}
	if !validRuleTypes[req.RuleType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule_type"})
		return
	}

	// 设置默认可信度
	if req.Confidence == 0 {
		req.Confidence = 80
	}
	if req.Confidence < 0 || req.Confidence > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Confidence must be between 0 and 100"})
		return
	}

	fingerprint := &models.Fingerprint{
		Name:        req.Name,
		Category:    req.Category,
		RuleType:    req.RuleType,
		RuleContent: req.RuleContent,
		Confidence:  req.Confidence,
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

	// 验证规则类型
	validRuleTypes := map[string]bool{
		"body": true, "header": true, "title": true, "favicon": true, "url": true,
	}
	if !validRuleTypes[req.RuleType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule_type"})
		return
	}

	if req.Confidence < 0 || req.Confidence > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Confidence must be between 0 and 100"})
		return
	}

	// 更新字段
	fingerprint.Name = req.Name
	fingerprint.Category = req.Category
	fingerprint.RuleType = req.RuleType
	fingerprint.RuleContent = req.RuleContent
	fingerprint.Confidence = req.Confidence
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
			RuleType:    req.RuleType,
			RuleContent: req.RuleContent,
			Confidence:  req.Confidence,
			Description: req.Description,
			IsEnabled:   true,
		}
		if fp.Confidence == 0 {
			fp.Confidence = 80
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

// ImportFingerprints 导入指纹 (支持JSON和YAML格式)
func (h *FingerprintHandler) ImportFingerprints(c *gin.Context) {
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

		// 将关键词数组转换为 JSON 字符串
		keywordJSON, err := json.Marshal(item.Keyword)
		if err != nil {
			reason := fmt.Sprintf("第%d条：关键词序列化失败 - %v", i+1, err)
			failedReasons = append(failedReasons, reason)
			fmt.Printf("  -> 跳过: %s\n", reason)
			failed++
			continue
		}

		// 构建规则内容：method:keywords_json
		ruleContent := fmt.Sprintf("%s:%s", item.Method, string(keywordJSON))

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
			RuleType:    ruleType,
			RuleContent: ruleContent,
			Confidence:  80, // 默认可信度
			Description: fmt.Sprintf("Imported from JSON - Method: %s, Location: %s", item.Method, item.Location),
			IsEnabled:   true,
		}

		fmt.Printf("  -> 成功创建指纹: %s (RuleContent: %s)\n", fingerprint.Name, fingerprint.RuleContent)
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

