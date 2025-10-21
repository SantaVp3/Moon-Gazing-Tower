package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// ScheduledTaskHandler 计划任务处理器
type ScheduledTaskHandler struct {
	cronManager *cron.Cron
}

// NewScheduledTaskHandler 创建计划任务处理器
func NewScheduledTaskHandler() *ScheduledTaskHandler {
	return &ScheduledTaskHandler{
		cronManager: cron.New(cron.WithSeconds()),
	}
}

// StartCronManager 启动cron管理器
func (h *ScheduledTaskHandler) StartCronManager() {
	h.cronManager.Start()
}

// StopCronManager 停止cron管理器
func (h *ScheduledTaskHandler) StopCronManager() {
	h.cronManager.Stop()
}

// CreateScheduledTaskRequest 创建计划任务请求
type CreateScheduledTaskRequest struct {
	Name        string              `json:"name" binding:"required"`
	Description string              `json:"description"`
	CronType    string              `json:"cron_type" binding:"required"`
	CronExpr    string              `json:"cron_expr"`
	TaskOptions models.TaskOptions  `json:"task_options" binding:"required"`
}

// ListScheduledTasks 列出所有计划任务
func (h *ScheduledTaskHandler) ListScheduledTasks(c *gin.Context) {
	cronType := c.Query("cron_type")
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

	query := database.DB.Model(&models.ScheduledTask{})

	if cronType != "" && cronType != "all" {
		query = query.Where("cron_type = ?", cronType)
	}
	if isEnabled != "" && isEnabled != "all" {
		query = query.Where("is_enabled = ?", isEnabled == "true")
	}

	var total int64
	query.Count(&total)

	var tasks []models.ScheduledTask
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scheduled tasks"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"scheduled_tasks": tasks,
		"total":           total,
		"page":            pageInt,
		"page_size":       pageSizeInt,
		"total_pages":     totalPages,
	})
}

// GetScheduledTask 获取单个计划任务
func (h *ScheduledTaskHandler) GetScheduledTask(c *gin.Context) {
	id := c.Param("id")

	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scheduled task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scheduled task"})
		return
	}

	c.JSON(http.StatusOK, task)
}

// CreateScheduledTask 创建计划任务
func (h *ScheduledTaskHandler) CreateScheduledTask(c *gin.Context) {
	var req CreateScheduledTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证cron类型
	validCronTypes := map[string]bool{
		"once": true, "daily": true, "weekly": true, "monthly": true, "custom": true,
	}
	if !validCronTypes[req.CronType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cron_type"})
		return
	}

	// 生成cron表达式
	cronExpr, err := h.generateCronExpr(req.CronType, req.CronExpr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 计算下次运行时间
	nextRun, err := h.calculateNextRun(cronExpr, req.CronType)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to calculate next run: %v", err)})
		return
	}

	userID := c.GetString("userID")

	scheduledTask := &models.ScheduledTask{
		Name:        req.Name,
		Description: req.Description,
		CronType:    req.CronType,
		CronExpr:    cronExpr,
		TaskOptions: req.TaskOptions,
		IsEnabled:   true,
		NextRunAt:   nextRun,
		RunCount:    0,
		FailCount:   0,
		CreatedBy:   userID,
	}

	if err := database.DB.Create(scheduledTask).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scheduled task"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":        "Scheduled task created successfully",
		"scheduled_task": scheduledTask,
	})
}

// UpdateScheduledTask 更新计划任务
func (h *ScheduledTaskHandler) UpdateScheduledTask(c *gin.Context) {
	id := c.Param("id")

	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scheduled task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scheduled task"})
		return
	}

	var req CreateScheduledTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证cron类型
	validCronTypes := map[string]bool{
		"once": true, "daily": true, "weekly": true, "monthly": true, "custom": true,
	}
	if !validCronTypes[req.CronType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid cron_type"})
		return
	}

	// 生成cron表达式
	cronExpr, err := h.generateCronExpr(req.CronType, req.CronExpr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 计算下次运行时间
	nextRun, err := h.calculateNextRun(cronExpr, req.CronType)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to calculate next run: %v", err)})
		return
	}

	// 更新字段
	task.Name = req.Name
	task.Description = req.Description
	task.CronType = req.CronType
	task.CronExpr = cronExpr
	task.TaskOptions = req.TaskOptions
	task.NextRunAt = nextRun

	if err := database.DB.Save(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scheduled task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Scheduled task updated successfully",
		"scheduled_task": task,
	})
}

// DeleteScheduledTask 删除计划任务
func (h *ScheduledTaskHandler) DeleteScheduledTask(c *gin.Context) {
	id := c.Param("id")

	if err := database.DB.Delete(&models.ScheduledTask{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scheduled task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Scheduled task deleted successfully"})
}

// ToggleScheduledTaskStatus 切换计划任务状态
func (h *ScheduledTaskHandler) ToggleScheduledTaskStatus(c *gin.Context) {
	id := c.Param("id")

	var task models.ScheduledTask
	if err := database.DB.First(&task, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scheduled task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scheduled task"})
		return
	}

	task.IsEnabled = !task.IsEnabled
	if err := database.DB.Save(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scheduled task status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Scheduled task status updated successfully",
		"is_enabled": task.IsEnabled,
	})
}

// RunScheduledTaskNow 立即运行计划任务
func (h *ScheduledTaskHandler) RunScheduledTaskNow(c *gin.Context) {
	id := c.Param("id")

	var scheduledTask models.ScheduledTask
	if err := database.DB.First(&scheduledTask, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scheduled task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get scheduled task"})
		return
	}

	// 创建任务
	task := &models.Task{
		Name:    fmt.Sprintf("%s (手动运行)", scheduledTask.Name),
		Target:  scheduledTask.TaskOptions.Target,
		Status:  models.TaskStatusPending,
		Options: scheduledTask.TaskOptions,
	}

	if err := database.DB.Create(task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
		return
	}

	// 记录执行日志
	log := &models.ScheduledTaskLog{
		ScheduledTaskID: scheduledTask.ID,
		TaskID:          task.ID,
		Status:          "success",
		Message:         "Task created successfully",
		StartTime:       time.Now(),
	}
	database.DB.Create(log)

	// 更新计划任务统计
	now := time.Now()
	scheduledTask.LastRunAt = &now
	scheduledTask.RunCount++
	database.DB.Save(&scheduledTask)

	c.JSON(http.StatusOK, gin.H{
		"message": "Scheduled task executed successfully",
		"task":    task,
	})
}

// GetScheduledTaskLogs 获取计划任务执行日志
func (h *ScheduledTaskHandler) GetScheduledTaskLogs(c *gin.Context) {
	id := c.Param("id")

	var logs []models.ScheduledTaskLog
	if err := database.DB.Where("scheduled_task_id = ?", id).
		Order("created_at DESC").
		Limit(100).
		Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"total": len(logs),
	})
}

// GetScheduledTaskStats 获取计划任务统计
func (h *ScheduledTaskHandler) GetScheduledTaskStats(c *gin.Context) {
	var totalTasks int64
	database.DB.Model(&models.ScheduledTask{}).Count(&totalTasks)

	var activeTasks int64
	database.DB.Model(&models.ScheduledTask{}).Where("is_enabled = ?", true).Count(&activeTasks)

	var totalRuns int64
	database.DB.Model(&models.ScheduledTask{}).Select("COALESCE(SUM(run_count), 0)").Scan(&totalRuns)

	var totalFails int64
	database.DB.Model(&models.ScheduledTask{}).Select("COALESCE(SUM(fail_count), 0)").Scan(&totalFails)

	c.JSON(http.StatusOK, gin.H{
		"total_tasks":   totalTasks,
		"active_tasks":  activeTasks,
		"total_runs":    totalRuns,
		"total_fails":   totalFails,
	})
}

// generateCronExpr 生成cron表达式
func (h *ScheduledTaskHandler) generateCronExpr(cronType, customExpr string) (string, error) {
	switch cronType {
	case "once":
		// 一次性任务，立即执行
		return "", nil
	case "daily":
		// 每天凌晨2点
		return "0 0 2 * * *", nil
	case "weekly":
		// 每周一凌晨2点
		return "0 0 2 * * 1", nil
	case "monthly":
		// 每月1号凌晨2点
		return "0 0 2 1 * *", nil
	case "custom":
		if customExpr == "" {
			return "", fmt.Errorf("custom cron expression is required")
		}
		// 验证cron表达式
		parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(customExpr); err != nil {
			return "", fmt.Errorf("invalid cron expression: %v", err)
		}
		return customExpr, nil
	default:
		return "", fmt.Errorf("invalid cron type: %s", cronType)
	}
}

// calculateNextRun 计算下次运行时间
func (h *ScheduledTaskHandler) calculateNextRun(cronExpr, cronType string) (*time.Time, error) {
	if cronType == "once" {
		// 一次性任务，立即执行
		now := time.Now()
		return &now, nil
	}

	if cronExpr == "" {
		return nil, fmt.Errorf("cron expression is empty")
	}

	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(cronExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cron expression: %v", err)
	}

	nextRun := schedule.Next(time.Now())
	return &nextRun, nil
}

// BatchDeleteScheduledTasks 批量删除计划任务
func (h *ScheduledTaskHandler) BatchDeleteScheduledTasks(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Where("id IN ?", req.IDs).Delete(&models.ScheduledTask{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scheduled tasks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scheduled tasks deleted successfully",
		"count":   len(req.IDs),
	})
}

// BatchToggleScheduledTasks 批量切换计划任务状态
func (h *ScheduledTaskHandler) BatchToggleScheduledTasks(c *gin.Context) {
	var req struct {
		IDs       []string `json:"ids" binding:"required"`
		IsEnabled bool     `json:"is_enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&models.ScheduledTask{}).
		Where("id IN ?", req.IDs).
		Update("is_enabled", req.IsEnabled).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scheduled tasks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Scheduled tasks status updated successfully",
		"count":      len(req.IDs),
		"is_enabled": req.IsEnabled,
	})
}

