package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// GitHubMonitorHandler GitHub监控处理器
type GitHubMonitorHandler struct{}

// NewGitHubMonitorHandler 创建GitHub监控处理器
func NewGitHubMonitorHandler() *GitHubMonitorHandler {
	return &GitHubMonitorHandler{}
}

// CreateGitHubMonitorRequest 创建GitHub监控请求
type CreateGitHubMonitorRequest struct {
	Name       string `json:"name" binding:"required"`
	Keywords   string `json:"keywords" binding:"required"`
	SearchType string `json:"search_type" binding:"required"`
	Language   string `json:"language"`
	User       string `json:"user"`
	Repository string `json:"repository"`
	Extension  string `json:"extension"`
	Interval   int    `json:"interval" binding:"required,min=600"` // 最小10分钟
}

// ListGitHubMonitors 列出所有GitHub监控
func (h *GitHubMonitorHandler) ListGitHubMonitors(c *gin.Context) {
	searchType := c.Query("search_type")
	isEnabled := c.Query("is_enabled")

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

	query := database.DB.Model(&models.GitHubMonitor{})

	if searchType != "" {
		query = query.Where("search_type = ?", searchType)
	}
	if isEnabled != "" {
		query = query.Where("is_enabled = ?", isEnabled == "true")
	}

	var total int64
	query.Count(&total)

	var monitors []models.GitHubMonitor
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&monitors).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch GitHub monitors"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"monitors":    monitors,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// GetGitHubMonitor 获取单个GitHub监控
func (h *GitHubMonitorHandler) GetGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	c.JSON(http.StatusOK, monitor)
}

// CreateGitHubMonitor 创建GitHub监控
func (h *GitHubMonitorHandler) CreateGitHubMonitor(c *gin.Context) {
	var req CreateGitHubMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证搜索类型
	validSearchTypes := map[string]bool{
		"code": true, "repository": true, "issue": true,
	}
	if !validSearchTypes[req.SearchType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid search_type"})
		return
	}

	nextRun := time.Now().Add(time.Duration(req.Interval) * time.Second)

	monitor := &models.GitHubMonitor{
		Name:       req.Name,
		Keywords:   req.Keywords,
		SearchType: req.SearchType,
		Language:   req.Language,
		User:       req.User,
		Repository: req.Repository,
		Extension:  req.Extension,
		IsEnabled:  true,
		Interval:   req.Interval,
		NextRunAt:  &nextRun,
		RunCount:   0,
	}

	if err := database.DB.Create(monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create GitHub monitor"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "GitHub monitor created successfully",
		"monitor": monitor,
	})
}

// UpdateGitHubMonitor 更新GitHub监控
func (h *GitHubMonitorHandler) UpdateGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	var req CreateGitHubMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证搜索类型
	validSearchTypes := map[string]bool{
		"code": true, "repository": true, "issue": true,
	}
	if !validSearchTypes[req.SearchType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid search_type"})
		return
	}

	// 更新字段
	monitor.Name = req.Name
	monitor.Keywords = req.Keywords
	monitor.SearchType = req.SearchType
	monitor.Language = req.Language
	monitor.User = req.User
	monitor.Repository = req.Repository
	monitor.Extension = req.Extension
	monitor.Interval = req.Interval

	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update GitHub monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub monitor updated successfully",
		"monitor": monitor,
	})
}

// DeleteGitHubMonitor 删除GitHub监控
func (h *GitHubMonitorHandler) DeleteGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.GitHubMonitor{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete GitHub monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "GitHub monitor deleted successfully"})
}

// ToggleGitHubMonitorStatus 切换GitHub监控状态
func (h *GitHubMonitorHandler) ToggleGitHubMonitorStatus(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	monitor.IsEnabled = !monitor.IsEnabled
	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update GitHub monitor status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "GitHub monitor status updated successfully",
		"is_enabled": monitor.IsEnabled,
	})
}

// ListGitHubMonitorResults 列出监控结果
func (h *GitHubMonitorHandler) ListGitHubMonitorResults(c *gin.Context) {
	monitorID := c.Param("id")
	isRead := c.Query("is_read")

	query := database.DB.Model(&models.GitHubMonitorResult{}).Where("monitor_id = ?", monitorID)

	if isRead != "" {
		query = query.Where("is_read = ?", isRead == "true")
	}

	var results []models.GitHubMonitorResult
	if err := query.Order("created_at DESC").Limit(100).Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
	})
}

// MarkResultAsRead 标记结果为已读
func (h *GitHubMonitorHandler) MarkResultAsRead(c *gin.Context) {
	resultID := c.Param("result_id")

	if err := database.DB.Model(&models.GitHubMonitorResult{}).
		Where("id = ?", resultID).
		Update("is_read", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark as read"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Result marked as read"})
}

// GetGitHubMonitorStats 获取GitHub监控统计
func (h *GitHubMonitorHandler) GetGitHubMonitorStats(c *gin.Context) {
	var totalMonitors int64
	database.DB.Model(&models.GitHubMonitor{}).Count(&totalMonitors)

	var activeMonitors int64
	database.DB.Model(&models.GitHubMonitor{}).Where("is_enabled = ?", true).Count(&activeMonitors)

	var totalResults int64
	database.DB.Model(&models.GitHubMonitorResult{}).Count(&totalResults)

	var unreadResults int64
	database.DB.Model(&models.GitHubMonitorResult{}).Where("is_read = ?", false).Count(&unreadResults)

	c.JSON(http.StatusOK, gin.H{
		"total_monitors":  totalMonitors,
		"active_monitors": activeMonitors,
		"total_results":   totalResults,
		"unread_results":  unreadResults,
	})
}

// RunGitHubMonitor 手动运行GitHub监控
func (h *GitHubMonitorHandler) RunGitHubMonitor(c *gin.Context) {
	id := c.Param("id")

	var monitor models.GitHubMonitor
	if err := database.DB.First(&monitor, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "GitHub monitor not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub monitor"})
		return
	}

	// 更新运行时间和计数
	now := time.Now()
	nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
	monitor.LastRunAt = &now
	monitor.NextRunAt = &nextRun
	monitor.RunCount++

	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update monitor"})
		return
	}

	// TODO: 实际执行GitHub搜索
	// 这里应该调用GitHub API进行搜索并保存结果

	c.JSON(http.StatusOK, gin.H{
		"message": "GitHub monitor executed successfully",
		"monitor": monitor,
	})
}

