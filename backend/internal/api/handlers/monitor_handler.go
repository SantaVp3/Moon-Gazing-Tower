package handlers

import (
	"fmt"
	"net/http"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/gin-gonic/gin"
)

// MonitorHandler 监控处理器
type MonitorHandler struct{}

// NewMonitorHandler 创建监控处理器
func NewMonitorHandler() *MonitorHandler {
	return &MonitorHandler{}
}

// CreateMonitorRequest 创建监控请求
type CreateMonitorRequest struct {
	Name         string              `json:"name" binding:"required"`
	Type         models.MonitorType  `json:"type"`
	Target       string              `json:"target" binding:"required"`
	Interval     int                 `json:"interval" binding:"required,min=1"` // 最小1小时
	AssetGroupID string              `json:"asset_group_id"`
	Options      map[string]bool     `json:"options"`
}

// CreateMonitor 创建监控任务
func (h *MonitorHandler) CreateMonitor(c *gin.Context) {
	var req CreateMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 如果没有指定类型，默认为domain
	if req.Type == "" {
		req.Type = models.MonitorTypeDomain
	}

	monitor := &models.Monitor{
		Name:     req.Name,
		Type:     req.Type,
		Target:   req.Target,
		Interval: req.Interval,
		Status:   models.MonitorStatusActive,
	}

	if err := database.DB.Create(monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create monitor"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Monitor created successfully",
		"monitor": monitor,
	})
}

// ListMonitors 列出所有监控任务
func (h *MonitorHandler) ListMonitors(c *gin.Context) {
	status := c.Query("status")
	monitorType := c.Query("type")

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

	query := database.DB.Model(&models.Monitor{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if monitorType != "" {
		query = query.Where("type = ?", monitorType)
	}

	var total int64
	query.Count(&total)

	var monitors []models.Monitor
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&monitors).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch monitors"})
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

// GetMonitor 获取监控详情
func (h *MonitorHandler) GetMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	var monitor models.Monitor
	if err := database.DB.First(&monitor, "id = ?", monitorID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}

	c.JSON(http.StatusOK, monitor)
}

// UpdateMonitorStatus 更新监控状态
func (h *MonitorHandler) UpdateMonitorStatus(c *gin.Context) {
	monitorID := c.Param("id")
	
	var req struct {
		Status models.MonitorStatus `json:"status" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&models.Monitor{}).Where("id = ?", monitorID).
		Update("status", req.Status).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update monitor status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Monitor status updated successfully"})
}

// DeleteMonitor 删除监控任务
func (h *MonitorHandler) DeleteMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	if err := database.DB.Delete(&models.Monitor{}, "id = ?", monitorID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Monitor deleted successfully"})
}

// ListMonitorResults 列出监控结果
func (h *MonitorHandler) ListMonitorResults(c *gin.Context) {
	monitorID := c.Param("id")

	var results []models.MonitorResult
	if err := database.DB.Where("monitor_id = ?", monitorID).
		Order("created_at DESC").
		Limit(100).
		Find(&results).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch monitor results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}
