package api

import (
	"log"
	"net/http"
	"strconv"

	"moongazing/models"
	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CruiseHandler 巡航任务处理器
type CruiseHandler struct {
	cruiseService *service.CruiseService
}

// NewCruiseHandler 创建巡航处理器
func NewCruiseHandler() *CruiseHandler {
	return &CruiseHandler{
		cruiseService: service.NewCruiseService(),
	}
}

// GetCruiseService 获取巡航服务（用于启动调度器）
func (h *CruiseHandler) GetCruiseService() *service.CruiseService {
	return h.cruiseService
}

// CreateCruise 创建巡航任务
// @Summary 创建巡航任务
// @Tags Cruise
// @Accept json
// @Produce json
// @Param request body models.CruiseTaskCreateRequest true "巡航任务信息"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises [post]
func (h *CruiseHandler) CreateCruise(c *gin.Context) {
	var req models.CruiseTaskCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[CruiseHandler] Failed to bind JSON: %v", err)
		utils.Error(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	log.Printf("[CruiseHandler] Creating cruise: %s, targets: %v", req.Name, req.Targets)

	// 验证必填字段
	if req.Name == "" {
		log.Printf("[CruiseHandler] Name is empty")
		utils.Error(c, http.StatusBadRequest, "Name is required")
		return
	}
	if req.CronExpr == "" {
		log.Printf("[CruiseHandler] CronExpr is empty")
		utils.Error(c, http.StatusBadRequest, "Cron expression is required")
		return
	}
	if len(req.Targets) == 0 {
		log.Printf("[CruiseHandler] Targets is empty")
		utils.Error(c, http.StatusBadRequest, "At least one target is required")
		return
	}

	// 获取用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		log.Printf("[CruiseHandler] User not authenticated")
		utils.Error(c, http.StatusUnauthorized, "User not authenticated")
		return
	}
	userObjID, _ := primitive.ObjectIDFromHex(userID.(string))
	log.Printf("[CruiseHandler] UserID: %s", userObjID.Hex())

	// 获取工作区ID（可选）
	var workspaceID primitive.ObjectID
	if wsID := c.GetHeader("X-Workspace-ID"); wsID != "" {
		workspaceID, _ = primitive.ObjectIDFromHex(wsID)
		log.Printf("[CruiseHandler] WorkspaceID: %s", workspaceID.Hex())
	} else {
		log.Printf("[CruiseHandler] No WorkspaceID provided")
	}

	cruise, err := h.cruiseService.CreateCruise(&req, userObjID, workspaceID)
	if err != nil {
		log.Printf("[CruiseHandler] Failed to create cruise: %v", err)
		utils.Error(c, http.StatusInternalServerError, "Failed to create cruise: "+err.Error())
		return
	}

	log.Printf("[CruiseHandler] Successfully created cruise: %s", cruise.ID.Hex())
	utils.Success(c, cruise)
}

// UpdateCruise 更新巡航任务
// @Summary 更新巡航任务
// @Tags Cruise
// @Accept json
// @Produce json
// @Param id path string true "巡航任务ID"
// @Param request body models.CruiseTaskUpdateRequest true "更新信息"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id} [put]
func (h *CruiseHandler) UpdateCruise(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	var req models.CruiseTaskUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.Error(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	if err := h.cruiseService.UpdateCruise(cruiseID, &req); err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to update cruise: "+err.Error())
		return
	}

	utils.Success(c, gin.H{"message": "Cruise updated successfully"})
}

// DeleteCruise 删除巡航任务
// @Summary 删除巡航任务
// @Tags Cruise
// @Param id path string true "巡航任务ID"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id} [delete]
func (h *CruiseHandler) DeleteCruise(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	if err := h.cruiseService.DeleteCruise(cruiseID); err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to delete cruise: "+err.Error())
		return
	}

	utils.Success(c, gin.H{"message": "Cruise deleted successfully"})
}

// GetCruise 获取单个巡航任务
// @Summary 获取巡航任务详情
// @Tags Cruise
// @Param id path string true "巡航任务ID"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id} [get]
func (h *CruiseHandler) GetCruise(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	cruise, err := h.cruiseService.GetCruise(cruiseID)
	if err != nil {
		utils.Error(c, http.StatusNotFound, "Cruise not found")
		return
	}

	utils.Success(c, cruise)
}

// ListCruises 列出巡航任务
// @Summary 列出巡航任务
// @Tags Cruise
// @Param page query int false "页码" default(1)
// @Param pageSize query int false "每页数量" default(10)
// @Param search query string false "搜索关键词"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises [get]
func (h *CruiseHandler) ListCruises(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	search := c.Query("search")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	// 获取工作区ID（可选）
	var workspaceID primitive.ObjectID
	if wsID := c.GetHeader("X-Workspace-ID"); wsID != "" {
		workspaceID, _ = primitive.ObjectIDFromHex(wsID)
	}

	cruises, total, err := h.cruiseService.ListCruises(workspaceID, page, pageSize, search)
	if err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to list cruises: "+err.Error())
		return
	}

	utils.Success(c, gin.H{
		"items":    cruises,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// EnableCruise 启用巡航任务
// @Summary 启用巡航任务
// @Tags Cruise
// @Param id path string true "巡航任务ID"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id}/enable [post]
func (h *CruiseHandler) EnableCruise(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	if err := h.cruiseService.EnableCruise(cruiseID); err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to enable cruise: "+err.Error())
		return
	}

	utils.Success(c, gin.H{"message": "Cruise enabled successfully"})
}

// DisableCruise 禁用巡航任务
// @Summary 禁用巡航任务
// @Tags Cruise
// @Param id path string true "巡航任务ID"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id}/disable [post]
func (h *CruiseHandler) DisableCruise(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	if err := h.cruiseService.DisableCruise(cruiseID); err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to disable cruise: "+err.Error())
		return
	}

	utils.Success(c, gin.H{"message": "Cruise disabled successfully"})
}

// RunNow 立即执行巡航任务
// @Summary 立即执行一次巡航任务
// @Tags Cruise
// @Param id path string true "巡航任务ID"
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id}/run [post]
func (h *CruiseHandler) RunNow(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	if err := h.cruiseService.RunNow(cruiseID); err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to run cruise: "+err.Error())
		return
	}

	utils.Success(c, gin.H{"message": "Cruise execution started"})
}

// GetCruiseLogs 获取巡航执行日志
// @Summary 获取巡航执行日志
// @Tags Cruise
// @Param id path string true "巡航任务ID"
// @Param page query int false "页码" default(1)
// @Param pageSize query int false "每页数量" default(10)
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/{id}/logs [get]
func (h *CruiseHandler) GetCruiseLogs(c *gin.Context) {
	cruiseID := c.Param("id")
	if cruiseID == "" {
		utils.Error(c, http.StatusBadRequest, "Cruise ID is required")
		return
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	logs, total, err := h.cruiseService.GetCruiseLogs(cruiseID, page, pageSize)
	if err != nil {
		utils.Error(c, http.StatusInternalServerError, "Failed to get logs: "+err.Error())
		return
	}

	utils.Success(c, gin.H{
		"items":    logs,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// GetCruiseStats 获取巡航统计
// @Summary 获取巡航统计信息
// @Tags Cruise
// @Success 200 {object} utils.Response
// @Router /api/v1/cruises/stats [get]
func (h *CruiseHandler) GetCruiseStats(c *gin.Context) {
	// 获取工作区ID（可选）
	var workspaceID primitive.ObjectID
	if wsID := c.GetHeader("X-Workspace-ID"); wsID != "" {
		workspaceID, _ = primitive.ObjectIDFromHex(wsID)
	}

	stats := h.cruiseService.GetStats(workspaceID)
	utils.Success(c, stats)
}
