package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/services"
)

// CreateTaskRequest 创建任务请求
type CreateTaskRequest struct {
	Name    string             `json:"name" binding:"required"`
	Target  string             `json:"target" binding:"required"`
	Options models.TaskOptions `json:"options"`
}

// TaskHandler 任务处理器
type TaskHandler struct {
	taskService *services.TaskService
}

// NewTaskHandler 创建任务处理器
func NewTaskHandler(taskService *services.TaskService) *TaskHandler {
	return &TaskHandler{
		taskService: taskService,
	}
}

// CreateTask 创建新任务
func (h *TaskHandler) CreateTask(c *gin.Context) {
	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task := &models.Task{
		Name:    req.Name,
		Target:  req.Target,
		Options: req.Options,
		Status:  models.TaskStatusPending,
	}

	if err := database.DB.Create(task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create task"})
		return
	}

	// 🆕 创建任务后不自动启动，等待用户手动启动
	// 任务状态保持为 pending

	c.JSON(http.StatusCreated, gin.H{
		"message": "Task created successfully. Please start it manually.",
		"task":    task,
	})
}

// GetTask 获取任务详情
func (h *TaskHandler) GetTask(c *gin.Context) {
	taskID := c.Param("id")

	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	c.JSON(http.StatusOK, task)
}

// ListTasks 列出所有任务
func (h *TaskHandler) ListTasks(c *gin.Context) {
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")
	status := c.Query("status")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 20
	}

	query := database.DB.Model(&models.Task{})

	if status != "" && status != "all" {
		query = query.Where("status = ?", status)
	}

	var total int64
	query.Count(&total)

	var tasks []models.Task
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tasks"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"tasks":       tasks,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// DeleteTask 删除任务及其所有相关资产数据
func (h *TaskHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")

	// 开启事务，确保所有删除操作都成功或都失败
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. 删除域名资产
	if err := tx.Where("task_id = ?", taskID).Delete(&models.Domain{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete domain assets"})
		return
	}

	// 2. 删除IP资产
	if err := tx.Where("task_id = ?", taskID).Delete(&models.IP{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete IP assets"})
		return
	}

	// 3. 删除端口资产
	if err := tx.Where("task_id = ?", taskID).Delete(&models.Port{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete port assets"})
		return
	}

	// 4. 删除站点资产
	if err := tx.Where("task_id = ?", taskID).Delete(&models.Site{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete site assets"})
		return
	}

	// 5. 删除任务本身
	if err := tx.Delete(&models.Task{}, "id = ?", taskID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete task"})
		return
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task and all related assets deleted successfully"})
}

// CancelTask 取消任务
func (h *TaskHandler) CancelTask(c *gin.Context) {
	taskID := c.Param("id")

	// 首先尝试取消正在运行的任务
	if err := h.taskService.CancelTask(taskID); err != nil {
		// 如果任务不在运行中，直接更新数据库状态
		if err := database.DB.Model(&models.Task{}).Where("id = ?", taskID).
			Update("status", models.TaskStatusCancelled).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel task"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Task cancelled successfully"})
}

// StartTask 手动启动任务
func (h *TaskHandler) StartTask(c *gin.Context) {
	taskID := c.Param("id")

	// 检查任务是否存在
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	// 只允许启动 pending 状态的任务
	if task.Status != models.TaskStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Cannot start task with status: %s. Only pending tasks can be started.", task.Status),
		})
		return
	}

	// 异步启动任务
	go h.taskService.ExecuteTask(task.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Task started successfully",
		"task_id": taskID,
	})
}

// GetTaskStats 获取任务统计信息
func (h *TaskHandler) GetTaskStats(c *gin.Context) {
	var stats struct {
		Total     int64 `json:"total"`
		Pending   int64 `json:"pending"`
		Running   int64 `json:"running"`
		Completed int64 `json:"completed"`
		Failed    int64 `json:"failed"`
	}

	database.DB.Model(&models.Task{}).Count(&stats.Total)
	database.DB.Model(&models.Task{}).Where("status = ?", models.TaskStatusPending).Count(&stats.Pending)
	database.DB.Model(&models.Task{}).Where("status = ?", models.TaskStatusRunning).Count(&stats.Running)
	database.DB.Model(&models.Task{}).Where("status = ?", models.TaskStatusCompleted).Count(&stats.Completed)
	database.DB.Model(&models.Task{}).Where("status = ?", models.TaskStatusFailed).Count(&stats.Failed)

	c.JSON(http.StatusOK, stats)
}
