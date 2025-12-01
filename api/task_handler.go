package api

import (
	"strconv"

	"moongazing/models"
	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TaskHandler struct {
	taskService *service.TaskService
}

func NewTaskHandler() *TaskHandler {
	return &TaskHandler{
		taskService: service.NewTaskService(),
	}
}

// ListTasks lists tasks with filtering and pagination
// GET /api/tasks
func (h *TaskHandler) ListTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	workspaceID := c.Query("workspace_id")
	taskType := c.Query("type")
	status := c.Query("status")
	
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	
	tasks, total, err := h.taskService.ListTasks(workspaceID, taskType, status, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.SuccessWithPagination(c, tasks, total, page, pageSize)
}

// GetTask gets a single task by ID
// GET /api/tasks/:id
func (h *TaskHandler) GetTask(c *gin.Context) {
	taskID := c.Param("id")
	
	task, err := h.taskService.GetTaskByID(taskID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.Success(c, task)
}

// CreateTask creates a new task
// POST /api/tasks
func (h *TaskHandler) CreateTask(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req struct {
		WorkspaceID string            `json:"workspace_id"`
		Name        string            `json:"name" binding:"required"`
		Description string            `json:"description"`
		Type        models.TaskType   `json:"type" binding:"required"`
		Targets     []string          `json:"targets" binding:"required"`
		TargetType  string            `json:"target_type" binding:"required"`
		Config      models.TaskConfig `json:"config"`
		IsScheduled bool              `json:"is_scheduled"`
		CronExpr    string            `json:"cron_expr"`
		Tags        []string          `json:"tags"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	task := &models.Task{
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Targets:     req.Targets,
		TargetType:  req.TargetType,
		Config:      req.Config,
		IsScheduled: req.IsScheduled,
		CronExpr:    req.CronExpr,
		Tags:        req.Tags,
	}
	
	if req.WorkspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(req.WorkspaceID)
		task.WorkspaceID = wsID
	}
	
	if userID != nil {
		uid, _ := primitive.ObjectIDFromHex(userID.(string))
		task.CreatedBy = uid
	}
	
	task.ResultStats = models.TaskResultStats{
		TotalTargets: len(req.Targets),
	}
	
	if err := h.taskService.CreateTask(task); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": task.ID.Hex()})
}

// UpdateTask updates a task
// PUT /api/tasks/:id
func (h *TaskHandler) UpdateTask(c *gin.Context) {
	taskID := c.Param("id")
	
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "created_at")
	delete(req, "status")
	
	if err := h.taskService.UpdateTask(taskID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeleteTask deletes a task
// DELETE /api/tasks/:id
func (h *TaskHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")
	
	if err := h.taskService.DeleteTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// StartTask starts a task
// POST /api/tasks/:id/start
func (h *TaskHandler) StartTask(c *gin.Context) {
	taskID := c.Param("id")
	
	if err := h.taskService.StartTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeTaskRunning, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "任务已启动", nil)
}

// PauseTask pauses a task
// POST /api/tasks/:id/pause
func (h *TaskHandler) PauseTask(c *gin.Context) {
	taskID := c.Param("id")
	
	if err := h.taskService.PauseTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "任务已暂停", nil)
}

// ResumeTask resumes a paused task
// POST /api/tasks/:id/resume
func (h *TaskHandler) ResumeTask(c *gin.Context) {
	taskID := c.Param("id")
	
	if err := h.taskService.ResumeTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "任务已恢复", nil)
}

// CancelTask cancels a task
// POST /api/tasks/:id/cancel
func (h *TaskHandler) CancelTask(c *gin.Context) {
	taskID := c.Param("id")
	
	if err := h.taskService.CancelTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "任务已取消", nil)
}

// RetryTask retries a failed task
// POST /api/tasks/:id/retry
func (h *TaskHandler) RetryTask(c *gin.Context) {
	taskID := c.Param("id")
	
	if err := h.taskService.RetryTask(taskID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "任务已重试", nil)
}

// RescanTask rescans a completed task
// POST /api/tasks/:id/rescan
func (h *TaskHandler) RescanTask(c *gin.Context) {
	taskID := c.Param("id")
	
	// 默认继续扫描（不从头开始）
	var req struct {
		FromScratch bool `json:"from_scratch"`
	}
	c.ShouldBindJSON(&req)
	
	if err := h.taskService.RescanTask(taskID, req.FromScratch); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	if req.FromScratch {
		utils.SuccessWithMessage(c, "任务已重新开始扫描", nil)
	} else {
		utils.SuccessWithMessage(c, "任务已继续扫描", nil)
	}
}

// GetTaskStats returns task statistics
// GET /api/tasks/stats
func (h *TaskHandler) GetTaskStats(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	
	stats, err := h.taskService.GetTaskStats(workspaceID)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.Success(c, stats)
}

// GetTaskLogs gets task logs
// GET /api/tasks/:id/logs
func (h *TaskHandler) GetTaskLogs(c *gin.Context) {
	taskID := c.Param("id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	
	logs, total, err := h.taskService.GetTaskLogs(taskID, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.SuccessWithPagination(c, logs, total, page, pageSize)
}

// ListTaskTemplates lists task templates
// GET /api/tasks/templates
func (h *TaskHandler) ListTaskTemplates(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	
	templates, err := h.taskService.ListTaskTemplates(workspaceID, nil)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.Success(c, templates)
}

// GetTaskTemplate gets a task template by ID
// GET /api/tasks/templates/:id
func (h *TaskHandler) GetTaskTemplate(c *gin.Context) {
	templateID := c.Param("id")
	
	template, err := h.taskService.GetTaskTemplate(templateID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.Success(c, template)
}

// CreateTaskTemplate creates a task template
// POST /api/tasks/templates
func (h *TaskHandler) CreateTaskTemplate(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req struct {
		WorkspaceID string            `json:"workspace_id"`
		Name        string            `json:"name" binding:"required"`
		Description string            `json:"description"`
		Type        models.TaskType   `json:"type" binding:"required"`
		Config      models.TaskConfig `json:"config"`
		IsPublic    bool              `json:"is_public"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	template := &models.TaskTemplate{
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Config:      req.Config,
		IsPublic:    req.IsPublic,
	}
	
	if req.WorkspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(req.WorkspaceID)
		template.WorkspaceID = wsID
	}
	
	if userID != nil {
		uid, _ := primitive.ObjectIDFromHex(userID.(string))
		template.CreatedBy = uid
	}
	
	if err := h.taskService.CreateTaskTemplate(template); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": template.ID.Hex()})
}

// DeleteTaskTemplate deletes a task template
// DELETE /api/tasks/templates/:id
func (h *TaskHandler) DeleteTaskTemplate(c *gin.Context) {
	templateID := c.Param("id")
	
	if err := h.taskService.DeleteTaskTemplate(templateID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// CreateTaskFromTemplate creates a task from template
// POST /api/tasks/from-template
func (h *TaskHandler) CreateTaskFromTemplate(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req struct {
		TemplateID  string   `json:"template_id" binding:"required"`
		WorkspaceID string   `json:"workspace_id"`
		Name        string   `json:"name" binding:"required"`
		Targets     []string `json:"targets" binding:"required"`
		TargetType  string   `json:"target_type" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	template, err := h.taskService.GetTaskTemplate(req.TemplateID)
	if err != nil {
		utils.NotFound(c, "模板不存在")
		return
	}
	
	task := &models.Task{
		Name:       req.Name,
		Type:       template.Type,
		Targets:    req.Targets,
		TargetType: req.TargetType,
		Config:     template.Config,
		ResultStats: models.TaskResultStats{
			TotalTargets: len(req.Targets),
		},
	}
	
	if req.WorkspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(req.WorkspaceID)
		task.WorkspaceID = wsID
	}
	
	if userID != nil {
		uid, _ := primitive.ObjectIDFromHex(userID.(string))
		task.CreatedBy = uid
	}
	
	if err := h.taskService.CreateTask(task); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": task.ID.Hex()})
}
