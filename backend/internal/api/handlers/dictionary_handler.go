package handlers

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// DictionaryHandler 字典处理器
type DictionaryHandler struct{}

// NewDictionaryHandler 创建字典处理器
func NewDictionaryHandler() *DictionaryHandler {
	return &DictionaryHandler{}
}

// ListDictionaries 获取字典列表
func (h *DictionaryHandler) ListDictionaries(c *gin.Context) {
	dictType := c.Query("type")       // port, directory, brute_force
	category := c.Query("category")   // ssh, mysql, common等
	search := c.Query("search")       // 搜索关键词
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	var dictionaries []models.Dictionary
	var total int64

	query := database.DB.Model(&models.Dictionary{})

	// 筛选
	if dictType != "" {
		query = query.Where("type = ?", dictType)
	}
	if category != "" {
		query = query.Where("category = ?", category)
	}
	if search != "" {
		query = query.Where("name LIKE ?", "%"+search+"%")
	}

	// 总数
	query.Count(&total)

	// 分页
	offset := (page - 1) * pageSize
	if err := query.Order("is_built_in DESC, created_at DESC").
		Offset(offset).Limit(pageSize).
		Find(&dictionaries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"dictionaries": dictionaries,
		"total":        total,
		"page":         page,
		"page_size":    pageSize,
	})
}

// GetDictionary 获取单个字典
func (h *DictionaryHandler) GetDictionary(c *gin.Context) {
	id := c.Param("id")

	var dictionary models.Dictionary
	if err := database.DB.First(&dictionary, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	c.JSON(http.StatusOK, dictionary)
}

// CreateDictionary 创建字典
func (h *DictionaryHandler) CreateDictionary(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Type        string `json:"type" binding:"required"`
		Category    string `json:"category"`
		Content     string `json:"content"`
		Description string `json:"description"`
		IsEnabled   bool   `json:"is_enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 计算字典大小
	size := 0
	if req.Content != "" {
		size = countLines(req.Content)
	}

	dictionary := models.Dictionary{
		Name:        req.Name,
		Type:        req.Type,
		Category:    req.Category,
		Content:     req.Content,
		Size:        size,
		IsBuiltIn:   false,
		IsEnabled:   req.IsEnabled,
		Description: req.Description,
	}

	if err := database.DB.Create(&dictionary).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, dictionary)
}

// UpdateDictionary 更新字典
func (h *DictionaryHandler) UpdateDictionary(c *gin.Context) {
	id := c.Param("id")

	var dictionary models.Dictionary
	if err := database.DB.First(&dictionary, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	// 内置字典不允许修改内容
	if dictionary.IsBuiltIn {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot modify built-in dictionary"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Category    string `json:"category"`
		Content     string `json:"content"`
		Description string `json:"description"`
		IsEnabled   *bool  `json:"is_enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	if req.Name != "" {
		dictionary.Name = req.Name
	}
	if req.Category != "" {
		dictionary.Category = req.Category
	}
	if req.Content != "" {
		dictionary.Content = req.Content
		dictionary.Size = countLines(req.Content)
	}
	if req.Description != "" {
		dictionary.Description = req.Description
	}
	if req.IsEnabled != nil {
		dictionary.IsEnabled = *req.IsEnabled
	}

	if err := database.DB.Save(&dictionary).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dictionary)
}

// DeleteDictionary 删除字典
func (h *DictionaryHandler) DeleteDictionary(c *gin.Context) {
	id := c.Param("id")

	var dictionary models.Dictionary
	if err := database.DB.First(&dictionary, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	// 内置字典不允许删除
	if dictionary.IsBuiltIn {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete built-in dictionary"})
		return
	}

	// 删除关联文件
	if dictionary.FilePath != "" {
		os.Remove(dictionary.FilePath)
	}

	if err := database.DB.Delete(&dictionary).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dictionary deleted successfully"})
}

// ToggleDictionary 启用/禁用字典
func (h *DictionaryHandler) ToggleDictionary(c *gin.Context) {
	id := c.Param("id")

	var dictionary models.Dictionary
	if err := database.DB.First(&dictionary, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	dictionary.IsEnabled = !dictionary.IsEnabled

	if err := database.DB.Save(&dictionary).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, dictionary)
}

// BatchDeleteDictionaries 批量删除字典
func (h *DictionaryHandler) BatchDeleteDictionaries(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查询要删除的字典
	var dictionaries []models.Dictionary
	if err := database.DB.Where("id IN ? AND is_built_in = ?", req.IDs, false).Find(&dictionaries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 删除关联文件
	for _, dict := range dictionaries {
		if dict.FilePath != "" {
			os.Remove(dict.FilePath)
		}
	}

	// 批量删除
	if err := database.DB.Where("id IN ? AND is_built_in = ?", req.IDs, false).Delete(&models.Dictionary{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Dictionaries deleted successfully",
		"deleted": len(dictionaries),
	})
}

// UploadDictionary 上传字典文件
func (h *DictionaryHandler) UploadDictionary(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	name := c.PostForm("name")
	dictType := c.PostForm("type")
	category := c.PostForm("category")
	description := c.PostForm("description")

	if name == "" || dictType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name and type are required"})
		return
	}

	// 创建上传目录
	uploadDir := filepath.Join("configs", "dicts", dictType)
	if category != "" {
		uploadDir = filepath.Join(uploadDir, category)
	}
	os.MkdirAll(uploadDir, 0755)

	// 保存文件
	filename := filepath.Join(uploadDir, file.Filename)
	if err := c.SaveUploadedFile(file, filename); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// 读取文件内容并计算大小
	content, size := readDictionaryFile(filename)

	dictionary := models.Dictionary{
		Name:        name,
		Type:        dictType,
		Category:    category,
		Content:     content,
		FilePath:    filename,
		Size:        size,
		IsBuiltIn:   false,
		IsEnabled:   true,
		Description: description,
	}

	if err := database.DB.Create(&dictionary).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, dictionary)
}

// DownloadDictionary 下载字典
func (h *DictionaryHandler) DownloadDictionary(c *gin.Context) {
	id := c.Param("id")

	var dictionary models.Dictionary
	if err := database.DB.First(&dictionary, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	// 如果有文件路径，直接下载文件
	if dictionary.FilePath != "" && fileExists(dictionary.FilePath) {
		c.FileAttachment(dictionary.FilePath, dictionary.Name+".txt")
		return
	}

	// 否则从Content生成临时文件
	if dictionary.Content != "" {
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.txt", dictionary.Name))
		c.Header("Content-Type", "text/plain")
		c.String(http.StatusOK, dictionary.Content)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary content not found"})
}

// GetDictionaryStats 获取字典统计信息
func (h *DictionaryHandler) GetDictionaryStats(c *gin.Context) {
	var stats struct {
		Total         int64            `json:"total"`
		ByType        map[string]int64 `json:"by_type"`
		ByCategory    map[string]int64 `json:"by_category"`
		Enabled       int64            `json:"enabled"`
		BuiltIn       int64            `json:"built_in"`
		TotalEntries  int              `json:"total_entries"`
	}

	// 总数
	database.DB.Model(&models.Dictionary{}).Count(&stats.Total)

	// 按类型统计
	stats.ByType = make(map[string]int64)
	var typeStats []struct {
		Type  string
		Count int64
	}
	database.DB.Model(&models.Dictionary{}).Select("type, COUNT(*) as count").Group("type").Scan(&typeStats)
	for _, ts := range typeStats {
		stats.ByType[ts.Type] = ts.Count
	}

	// 按分类统计
	stats.ByCategory = make(map[string]int64)
	var categoryStats []struct {
		Category string
		Count    int64
	}
	database.DB.Model(&models.Dictionary{}).Select("category, COUNT(*) as count").Group("category").Scan(&categoryStats)
	for _, cs := range categoryStats {
		if cs.Category != "" {
			stats.ByCategory[cs.Category] = cs.Count
		}
	}

	// 启用的字典数量
	database.DB.Model(&models.Dictionary{}).Where("is_enabled = ?", true).Count(&stats.Enabled)

	// 内置字典数量
	database.DB.Model(&models.Dictionary{}).Where("is_built_in = ?", true).Count(&stats.BuiltIn)

	// 总条目数
	var dictionaries []models.Dictionary
	database.DB.Find(&dictionaries)
	for _, dict := range dictionaries {
		stats.TotalEntries += dict.Size
	}

	c.JSON(http.StatusOK, stats)
}

// 辅助函数：统计行数
func countLines(text string) int {
	if text == "" {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// 辅助函数：读取字典文件
func readDictionaryFile(filename string) (string, int) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0
	}
	defer file.Close()

	var content strings.Builder
	count := 0
	scanner := bufio.NewScanner(file)
	
	// 最多读取前1000行作为预览
	for scanner.Scan() && count < 1000 {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			content.WriteString(line + "\n")
			count++
		}
	}

	// 继续计数剩余行
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}

	return content.String(), count
}

// 辅助函数：检查文件是否存在
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

