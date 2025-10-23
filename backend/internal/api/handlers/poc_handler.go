package handlers

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

// PoCHandler PoC处理器
type PoCHandler struct{}

// NewPoCHandler 创建PoC处理器
func NewPoCHandler() *PoCHandler {
	return &PoCHandler{}
}

// CreatePoCRequest 创建PoC请求 (支持YAML)
type CreatePoCRequest struct {
	Name        string `json:"name" yaml:"name" binding:"required"`
	Category    string `json:"category" yaml:"category" binding:"required"`
	Severity    string `json:"severity" yaml:"severity" binding:"required"`
	CVE         string `json:"cve" yaml:"cve"`
	Author      string `json:"author" yaml:"author"`
	Description string `json:"description" yaml:"description"`
	Reference   string `json:"reference" yaml:"reference"`
	PoCType     string `json:"poc_type" yaml:"poc_type" binding:"required"`
	PoCContent  string `json:"poc_content" yaml:"poc_content" binding:"required"`
	Tags        string `json:"tags" yaml:"tags"`
}

// ListPoCs 列出所有PoC
func (h *PoCHandler) ListPoCs(c *gin.Context) {
	category := c.Query("category")
	severity := c.Query("severity")
	pocType := c.Query("poc_type")
	name := c.Query("name")
	cve := c.Query("cve")
	tags := c.Query("tags")

	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var pageInt, pageSizeInt int
	if _, err := fmt.Sscanf(page, "%d", &pageInt); err != nil || pageInt < 1 {
		pageInt = 1
	}
	if _, err := fmt.Sscanf(pageSize, "%d", &pageSizeInt); err != nil || pageSizeInt < 1 {
		pageSizeInt = 20
	}
	// 限制单页最大数量，防止查询过多数据导致性能问题
	const maxPageSize = 100
	if pageSizeInt > maxPageSize {
		pageSizeInt = maxPageSize
	}

	query := database.DB.Model(&models.PoC{})

	if category != "" {
		query = query.Where("category = ?", category)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if pocType != "" {
		query = query.Where("poc_type = ?", pocType)
	}
	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}
	if cve != "" {
		query = query.Where("cve LIKE ?", "%"+cve+"%")
	}
	if tags != "" {
		query = query.Where("tags LIKE ?", "%"+tags+"%")
	}

	var total int64
	query.Count(&total)

	var pocs []models.PoC
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&pocs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch PoCs"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"pocs":        pocs,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// GetPoC 获取单个PoC
func (h *PoCHandler) GetPoC(c *gin.Context) {
	id := c.Param("id")

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PoC"})
		return
	}

	c.JSON(http.StatusOK, poc)
}

// CreatePoC 创建PoC
func (h *PoCHandler) CreatePoC(c *gin.Context) {
	var req CreatePoCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证严重等级
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[req.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid severity"})
		return
	}

	// 验证PoC类型
	validPoCTypes := map[string]bool{
		"nuclei": true, "xray": true, "custom": true,
	}
	if !validPoCTypes[req.PoCType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid poc_type"})
		return
	}

	userID := c.GetString("userID")

	poc := &models.PoC{
		Name:        req.Name,
		Category:    req.Category,
		Severity:    req.Severity,
		CVE:         req.CVE,
		Author:      req.Author,
		Description: req.Description,
		Reference:   req.Reference,
		PoCType:     req.PoCType,
		PoCContent:  req.PoCContent,
		Tags:        req.Tags,
		IsEnabled:   true,
		CreatedBy:   userID,
	}

	if err := database.DB.Create(poc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create PoC"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "PoC created successfully",
		"poc":     poc,
	})
}

// UpdatePoC 更新PoC
func (h *PoCHandler) UpdatePoC(c *gin.Context) {
	id := c.Param("id")

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PoC"})
		return
	}

	var req CreatePoCRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证严重等级
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	if !validSeverities[req.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid severity"})
		return
	}

	// 验证PoC类型
	validPoCTypes := map[string]bool{
		"nuclei": true, "xray": true, "custom": true,
	}
	if !validPoCTypes[req.PoCType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid poc_type"})
		return
	}

	// 更新字段
	poc.Name = req.Name
	poc.Category = req.Category
	poc.Severity = req.Severity
	poc.CVE = req.CVE
	poc.Author = req.Author
	poc.Description = req.Description
	poc.Reference = req.Reference
	poc.PoCType = req.PoCType
	poc.PoCContent = req.PoCContent
	poc.Tags = req.Tags

	if err := database.DB.Save(&poc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update PoC"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC updated successfully",
		"poc":     poc,
	})
}

// DeletePoC 删除PoC
func (h *PoCHandler) DeletePoC(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.PoC{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete PoC"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "PoC deleted successfully"})
}

// TogglePoCStatus 切换PoC启用状态
func (h *PoCHandler) TogglePoCStatus(c *gin.Context) {
	id := c.Param("id")

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get PoC"})
		return
	}

	poc.IsEnabled = !poc.IsEnabled
	if err := database.DB.Save(&poc).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update PoC status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "PoC status updated successfully",
		"is_enabled": poc.IsEnabled,
	})
}

// BatchImportPoCs 批量导入PoC (仅支持YAML格式)
func (h *PoCHandler) BatchImportPoCs(c *gin.Context) {
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
		bodyStr := strings.TrimSpace(string(body))
		// YAML 通常不以 "[" 或 "{" 开头
		if !strings.HasPrefix(bodyStr, "[") && !strings.HasPrefix(bodyStr, "{") {
			isYAML = true
		}
	}

	var pocs []CreatePoCRequest

	if !isYAML {
		// 不再支持 JSON 格式
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only YAML format is supported. JSON format is no longer supported."})
		return
	}

	fmt.Println("检测到 YAML 格式，开始解析...")

	// 首先尝试解析为数组格式（批量导入）
	if err := yaml.Unmarshal(body, &pocs); err != nil {
		fmt.Printf("尝试作为数组解析失败: %v，尝试作为Nuclei模板解析...\n", err)

		// 尝试解析为多文档YAML（使用 --- 分隔符）
		bodyStr := string(body)
		documents := strings.Split(bodyStr, "\n---\n")

		fmt.Printf("检测到 %d 个YAML文档\n", len(documents))

		for i, doc := range documents {
			doc = strings.TrimSpace(doc)
			if doc == "" || doc == "---" {
				continue
			}

			fmt.Printf("解析第 %d 个文档（前100字符）: %s...\n", i+1, doc[:min(100, len(doc))])

			// 尝试解析为Nuclei模板格式（单个对象）
			var nucleiTemplate map[string]interface{}
			if err := yaml.Unmarshal([]byte(doc), &nucleiTemplate); err != nil {
				fmt.Printf("⚠️ 文档 %d YAML解析错误: %v\n", i+1, err)
				continue
			}

			// 转换Nuclei模板为CreatePoCRequest
			poc, err := convertNucleiTemplate(nucleiTemplate)
			if err != nil {
				fmt.Printf("⚠️ 文档 %d Nuclei模板转换错误: %v\n", i+1, err)
				continue
			}

			pocs = append(pocs, poc)
			fmt.Printf("✅ 文档 %d 解析成功: Name=%s, Category=%s, Severity=%s\n", i+1, poc.Name, poc.Category, poc.Severity)
		}

		if len(pocs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No valid PoC templates found in the uploaded file"})
			return
		}
	}

	fmt.Printf("接收到 %d 条 PoC 数据\n", len(pocs))

	// 限制单次导入数量，防止数据过大导致超时或内存溢出
	const maxBatchSize = 1000
	if len(pocs) > maxBatchSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   fmt.Sprintf("Too many PoCs in one batch. Maximum allowed: %d, received: %d", maxBatchSize, len(pocs)),
			"message": fmt.Sprintf("请将PoC分批上传，单次最多 %d 条", maxBatchSize),
		})
		return
	}

	userID := c.GetString("userID")
	var created []models.PoC
	var failed int
	var skipped int

	for i, req := range pocs {
		fmt.Printf("处理第 %d 条: Name=%s, Category=%s, Severity=%s\n",
			i+1, req.Name, req.Category, req.Severity)

		// 验证必填字段
		if req.Name == "" || req.Category == "" || req.Severity == "" || req.PoCType == "" || req.PoCContent == "" {
			fmt.Printf("  -> ❌ 跳过: 缺少必填字段 (Name=%q, Category=%q, Severity=%q, PoCType=%q, ContentLen=%d)\n",
				req.Name, req.Category, req.Severity, req.PoCType, len(req.PoCContent))
			failed++
			continue
		}

		// 检查是否已存在相同的 PoC（去重）
		var existingPoC models.PoC
		if err := database.DB.Where("name = ? AND cve = ?", req.Name, req.CVE).First(&existingPoC).Error; err == nil {
			fmt.Printf("  -> 跳过（已存在）: %s\n", req.Name)
			skipped++
			continue
		}

		poc := models.PoC{
			Name:        req.Name,
			Category:    req.Category,
			Severity:    req.Severity,
			CVE:         req.CVE,
			Author:      req.Author,
			Description: req.Description,
			Reference:   req.Reference,
			PoCType:     req.PoCType,
			PoCContent:  req.PoCContent,
			Tags:        req.Tags,
			IsEnabled:   true,
			CreatedBy:   userID,
		}
		created = append(created, poc)
		fmt.Printf("  -> 成功创建 PoC: %s\n", poc.Name)
	}

	// 批量插入 - 分批处理，每批最多100条
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
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":          "Failed to import PoCs: " + err.Error(),
					"imported_count": i,
					"skipped_count":  skipped,
					"failed_count":   failed + (len(created) - i),
					"total":          len(pocs),
				})
				return
			}
			fmt.Printf("✅ 批量插入成功 (batch %d-%d)\n", i, end)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "PoCs imported successfully",
		"imported_count": len(created),
		"skipped_count":  skipped,
		"failed_count":   failed,
		"total":          len(pocs),
	})
}

// GetPoCCategories 获取所有分类
func (h *PoCHandler) GetPoCCategories(c *gin.Context) {
	var categories []string
	database.DB.Model(&models.PoC{}).
		Distinct("category").
		Pluck("category", &categories)

	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

// GetPoCStats 获取PoC统计信息
func (h *PoCHandler) GetPoCStats(c *gin.Context) {
	var total int64
	database.DB.Model(&models.PoC{}).Count(&total)

	var severityStats []struct {
		Severity string
		Count    int64
	}
	database.DB.Model(&models.PoC{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Scan(&severityStats)

	var categoryStats []struct {
		Category string
		Count    int64
	}
	database.DB.Model(&models.PoC{}).
		Select("category, COUNT(*) as count").
		Group("category").
		Order("count DESC").
		Limit(10).
		Scan(&categoryStats)

	c.JSON(http.StatusOK, gin.H{
		"total":          total,
		"severity_stats": severityStats,
		"category_stats": categoryStats,
	})
}

// ExecutePoC 执行PoC
func (h *PoCHandler) ExecutePoC(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Target string `json:"target" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var poc models.PoC
	if err := database.DB.First(&poc, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "PoC not found"})
		return
	}

	// 检查 PoC 是否启用
	if !poc.IsEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PoC is disabled"})
		return
	}

	// 使用新的PoC执行器
	executor := scanner.NewPoCExecutor()
	execResult, err := executor.Execute(&poc, req.Target)

	// 记录执行日志
	logResult := "safe"
	details := ""

	if err != nil {
		logResult = "error"
		details = fmt.Sprintf("Execution failed: %v", err)
	} else if execResult.Vulnerable {
		logResult = "vulnerable"
		details = execResult.Details
	} else {
		details = execResult.Message
	}

	log := &models.PoCExecutionLog{
		PoCID:   poc.ID,
		Target:  req.Target,
		Result:  logResult,
		Details: details,
	}
	database.DB.Create(log)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "PoC execution failed",
			"message": err.Error(),
			"result":  logResult,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC executed successfully",
		"result":  logResult,
		"details": details,
	})
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ImportPoCsFromZip 从zip文件批量导入PoC
func (h *PoCHandler) ImportPoCsFromZip(c *gin.Context) {
	// 获取上传的zip文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get uploaded file: " + err.Error()})
		return
	}

	// 检查文件扩展名
	if !strings.HasSuffix(strings.ToLower(file.Filename), ".zip") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Only .zip files are supported"})
		return
	}

	// 限制文件大小（100MB）
	const maxFileSize = 100 * 1024 * 1024
	if file.Size > maxFileSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("File too large. Maximum size: %dMB, uploaded: %.2fMB",
				maxFileSize/(1024*1024), float64(file.Size)/(1024*1024)),
		})
		return
	}

	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), fmt.Sprintf("poc_import_%s", c.GetString("userID")))
	os.RemoveAll(tempDir) // 清理可能存在的旧目录
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp directory"})
		return
	}
	defer os.RemoveAll(tempDir) // 清理临时目录

	// 保存上传的zip文件
	zipPath := filepath.Join(tempDir, file.Filename)
	if err := c.SaveUploadedFile(file, zipPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save uploaded file"})
		return
	}

	// 解压zip文件
	extractDir := filepath.Join(tempDir, "extracted")
	if err := unzipFile(zipPath, extractDir); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to extract zip file: " + err.Error()})
		return
	}

	// 递归查找所有yaml文件
	var yamlFiles []string
	err = filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				yamlFiles = append(yamlFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan yaml files: " + err.Error()})
		return
	}

	if len(yamlFiles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No YAML files found in the zip archive"})
		return
	}

	fmt.Printf("📦 找到 %d 个YAML文件，开始批量导入...\n", len(yamlFiles))

	// 批量导入PoC
	userID := c.GetString("userID")
	var created []models.PoC
	var skipped int
	var failed int
	var failedFiles []string

	for _, yamlPath := range yamlFiles {
		relPath, _ := filepath.Rel(extractDir, yamlPath)
		fmt.Printf("📄 处理文件: %s\n", relPath)

		// 读取yaml文件内容
		content, err := os.ReadFile(yamlPath)
		if err != nil {
			fmt.Printf("  ❌ 读取失败: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// 尝试解析为Nuclei模板
		var template map[string]interface{}
		if err := yaml.Unmarshal(content, &template); err != nil {
			fmt.Printf("  ❌ YAML解析失败: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// 转换为CreatePoCRequest
		poc, err := convertNucleiTemplate(template)
		if err != nil {
			fmt.Printf("  ❌ 模板转换失败: %v\n", err)
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// 验证必填字段
		if poc.Name == "" || poc.Category == "" || poc.Severity == "" || poc.PoCType == "" || poc.PoCContent == "" {
			fmt.Printf("  ⏭️ 跳过: 缺少必填字段\n")
			failed++
			failedFiles = append(failedFiles, relPath)
			continue
		}

		// 检查是否已存在（去重）
		var existingPoC models.PoC
		if err := database.DB.Where("name = ? AND cve = ?", poc.Name, poc.CVE).First(&existingPoC).Error; err == nil {
			fmt.Printf("  ⏭️ 跳过（已存在）: %s\n", poc.Name)
			skipped++
			continue
		}

		// 添加到待创建列表
		pocModel := models.PoC{
			Name:        poc.Name,
			Category:    poc.Category,
			Severity:    poc.Severity,
			CVE:         poc.CVE,
			Author:      poc.Author,
			Description: poc.Description,
			Reference:   poc.Reference,
			PoCType:     poc.PoCType,
			PoCContent:  poc.PoCContent,
			Tags:        poc.Tags,
			IsEnabled:   true,
			CreatedBy:   userID,
		}
		created = append(created, pocModel)
		fmt.Printf("  ✅ 准备导入: %s\n", poc.Name)
	}

	// 批量插入到数据库（分批处理，每批100条）
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
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":          "Failed to import PoCs: " + err.Error(),
					"imported_count": i,
					"skipped_count":  skipped,
					"failed_count":   failed + (len(created) - i),
					"failed_files":   failedFiles,
					"total_files":    len(yamlFiles),
				})
				return
			}
			fmt.Printf("✅ 批量插入成功 (batch %d-%d)\n", i, end)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "PoCs imported from zip successfully",
		"imported_count": len(created),
		"skipped_count":  skipped,
		"failed_count":   failed,
		"failed_files":   failedFiles,
		"total_files":    len(yamlFiles),
	})
}

// unzipFile 解压zip文件到指定目录
func unzipFile(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	for _, f := range r.File {
		// 防止路径遍历攻击
		fpath := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, f.Mode())
			continue
		}

		// 创建父目录
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return err
		}

		// 解压文件
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

// convertNucleiTemplate 转换Nuclei模板为CreatePoCRequest
func convertNucleiTemplate(template map[string]interface{}) (CreatePoCRequest, error) {
	var req CreatePoCRequest

	// 提取ID作为CVE编号
	if id, ok := template["id"].(string); ok {
		req.CVE = id
	}

	// 提取info部分
	info, ok := template["info"].(map[string]interface{})
	if !ok {
		return req, fmt.Errorf("missing 'info' section")
	}

	// 提取name（必填）
	if name, ok := info["name"].(string); ok {
		req.Name = name
	} else {
		// 如果没有name，尝试使用ID作为name
		if req.CVE != "" {
			req.Name = req.CVE
		} else {
			return req, fmt.Errorf("missing 'name' in info section and no ID available")
		}
	}

	// 提取author
	if author, ok := info["author"].(string); ok {
		req.Author = author
	}

	// 提取severity
	if severity, ok := info["severity"].(string); ok {
		req.Severity = severity
	} else {
		req.Severity = "medium" // 默认值
	}

	// 提取description
	if desc, ok := info["description"].(string); ok {
		req.Description = strings.TrimSpace(desc)
	}

	// 提取reference（可能是数组或字符串）
	if ref, ok := info["reference"]; ok {
		switch v := ref.(type) {
		case []interface{}:
			refs := make([]string, 0, len(v))
			for _, r := range v {
				if refStr, ok := r.(string); ok {
					refs = append(refs, refStr)
				}
			}
			req.Reference = strings.Join(refs, "\n")
		case string:
			req.Reference = v
		}
	}

	// 提取tags
	if tags, ok := info["tags"].(string); ok {
		req.Tags = tags
	}

	// 提取CVE ID（从classification或直接从info）
	if classification, ok := info["classification"].(map[string]interface{}); ok {
		if cveID, ok := classification["cve-id"].(string); ok {
			req.CVE = cveID
		}
	}

	// 设置category（从tags中提取）
	if req.Tags != "" {
		tagList := strings.Split(req.Tags, ",")
		if len(tagList) > 0 {
			req.Category = strings.TrimSpace(tagList[0])
		}
	}
	if req.Category == "" {
		req.Category = "其他" // 默认分类
	}

	// 将整个模板作为PoC内容（转回YAML）
	templateBytes, err := yaml.Marshal(template)
	if err != nil {
		return req, fmt.Errorf("failed to marshal template: %w", err)
	}
	req.PoCContent = string(templateBytes)
	req.PoCType = "nuclei" // 设置PoC类型为nuclei

	return req, nil
}
