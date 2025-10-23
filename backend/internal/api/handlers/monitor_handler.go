package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// MonitorHandler 监控处理器
type MonitorHandler struct{}

// NewMonitorHandler 创建监控处理器
func NewMonitorHandler() *MonitorHandler {
	return &MonitorHandler{}
}

// CreateMonitorRequest 创建监控请求
type CreateMonitorRequest struct {
	Name               string                     `json:"name" binding:"required"`
	Type               models.MonitorType         `json:"type"`
	Target             string                     `json:"target" binding:"required"`
	Interval           int                        `json:"interval" binding:"required,min=1"` // 单位：小时
	AssetGroupID       string                     `json:"asset_group_id"`
	Options            *models.MonitorOptions     `json:"options"`
	NotificationConfig *models.NotificationConfig `json:"notification_config"`
}

// UpdateMonitorRequest 更新监控请求
type UpdateMonitorRequest struct {
	Name               string                     `json:"name"`
	Target             string                     `json:"target"`
	Interval           int                        `json:"interval"`
	Options            *models.MonitorOptions     `json:"options"`
	NotificationConfig *models.NotificationConfig `json:"notification_config"`
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

	// 转换interval：前端是小时，后端存储为秒
	intervalInSeconds := req.Interval * 3600

	// 序列化options
	var optionsJSON string
	if req.Options != nil {
		optionsBytes, _ := json.Marshal(req.Options)
		optionsJSON = string(optionsBytes)
	}

	// 序列化notification config
	var notificationJSON string
	if req.NotificationConfig != nil {
		notificationBytes, _ := json.Marshal(req.NotificationConfig)
		notificationJSON = string(notificationBytes)
	}

	monitor := &models.Monitor{
		Name:               req.Name,
		Type:               req.Type,
		Target:             req.Target,
		Interval:           intervalInSeconds,
		AssetGroupID:       req.AssetGroupID,
		Options:            optionsJSON,
		NotificationConfig: notificationJSON,
		Status:             models.MonitorStatusActive,
		RunCount:           0,
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

// UpdateMonitor 更新监控任务
func (h *MonitorHandler) UpdateMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	var monitor models.Monitor
	if err := database.DB.First(&monitor, "id = ?", monitorID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Monitor not found"})
		return
	}

	var req UpdateMonitorRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	if req.Name != "" {
		monitor.Name = req.Name
	}
	if req.Target != "" {
		monitor.Target = req.Target
	}
	if req.Interval > 0 {
		monitor.Interval = req.Interval * 3600 // 转换为秒
	}

	// 更新options
	if req.Options != nil {
		optionsBytes, _ := json.Marshal(req.Options)
		monitor.Options = string(optionsBytes)
	}

	// 更新notification config
	if req.NotificationConfig != nil {
		notificationBytes, _ := json.Marshal(req.NotificationConfig)
		monitor.NotificationConfig = string(notificationBytes)
	}

	if err := database.DB.Save(&monitor).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update monitor"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Monitor updated successfully",
		"monitor": monitor,
	})
}

// DeleteMonitor 删除监控任务
func (h *MonitorHandler) DeleteMonitor(c *gin.Context) {
	monitorID := c.Param("id")

	// 删除监控及其结果
	tx := database.DB.Begin()

	// 删除监控结果
	if err := tx.Delete(&models.MonitorResult{}, "monitor_id = ?", monitorID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor results"})
		return
	}

	// 删除监控
	if err := tx.Delete(&models.Monitor{}, "id = ?", monitorID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor"})
		return
	}

	tx.Commit()
	c.JSON(http.StatusOK, gin.H{"message": "Monitor deleted successfully"})
}

// BatchDeleteMonitors 批量删除监控任务
func (h *MonitorHandler) BatchDeleteMonitors(c *gin.Context) {
	var req struct {
		MonitorIDs []string `json:"monitor_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(req.MonitorIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No monitor IDs provided"})
		return
	}

	tx := database.DB.Begin()

	// 删除所有相关结果
	if err := tx.Where("monitor_id IN ?", req.MonitorIDs).Delete(&models.MonitorResult{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitor results"})
		return
	}

	// 删除所有监控
	if err := tx.Where("id IN ?", req.MonitorIDs).Delete(&models.Monitor{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete monitors"})
		return
	}

	tx.Commit()
	c.JSON(http.StatusOK, gin.H{
		"message": "Monitors deleted successfully",
		"count":   len(req.MonitorIDs),
	})
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
