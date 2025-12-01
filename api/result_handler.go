package api

import (
"moongazing/models"
"moongazing/service"
"moongazing/utils"
"strconv"

"github.com/gin-gonic/gin"
)

type ResultHandler struct {
	resultService *service.ResultService
}

func NewResultHandler() *ResultHandler {
	return &ResultHandler{
		resultService: service.NewResultService(),
	}
}

// GetTaskResults 获取任务扫描结果
func (h *ResultHandler) GetTaskResults(c *gin.Context) {
	taskID := c.Param("id")
	resultType := models.ResultType(c.Query("type"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	search := c.Query("search")
	statusCode, _ := strconv.Atoi(c.DefaultQuery("status_code", "0")) // 状态码筛选

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	results, total, err := h.resultService.GetResultsByTask(taskID, resultType, page, pageSize, search, statusCode)
	if err != nil {
		utils.Error(c, 500, "获取结果失败: "+err.Error())
		return
	}

	utils.SuccessWithPagination(c, results, total, page, pageSize)
}

// GetTaskResultStats 获取任务结果统计
func (h *ResultHandler) GetTaskResultStats(c *gin.Context) {
	taskID := c.Param("id")

	stats, err := h.resultService.GetResultStats(taskID)
	if err != nil {
		utils.Error(c, 500, "获取统计失败: "+err.Error())
		return
	}

	utils.Success(c, stats)
}

// GetSubdomainResults 获取子域名结果
func (h *ResultHandler) GetSubdomainResults(c *gin.Context) {
	taskID := c.Param("id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	search := c.Query("search")

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	results, total, err := h.resultService.GetSubdomainResults(taskID, page, pageSize, search)
	if err != nil {
		utils.Error(c, 500, "获取结果失败: "+err.Error())
		return
	}

	utils.SuccessWithPagination(c, results, total, page, pageSize)
}

// ExportResults 导出结果
func (h *ResultHandler) ExportResults(c *gin.Context) {
	taskID := c.Param("id")
	resultType := models.ResultType(c.Query("type"))

	results, err := h.resultService.ExportResults(taskID, resultType)
	if err != nil {
		utils.Error(c, 500, "导出失败: "+err.Error())
		return
	}

	utils.SuccessWithPagination(c, results, int64(len(results)), 1, len(results))
}

// UpdateResultTags 更新结果标签
func (h *ResultHandler) UpdateResultTags(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Tags []string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.resultService.UpdateResultTags(id, req.Tags); err != nil {
		utils.Error(c, 500, "更新失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "更新成功", nil)
}

// AddResultTag 添加标签
func (h *ResultHandler) AddResultTag(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Tag string `json:"tag"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Tag == "" {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.resultService.AddResultTag(id, req.Tag); err != nil {
		utils.Error(c, 500, "添加失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "添加成功", nil)
}

// RemoveResultTag 移除标签
func (h *ResultHandler) RemoveResultTag(c *gin.Context) {
	id := c.Param("id")
	tag := c.Query("tag")

	if tag == "" {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.resultService.RemoveResultTag(id, tag); err != nil {
		utils.Error(c, 500, "移除失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "移除成功", nil)
}

// BatchDeleteResults 批量删除结果
func (h *ResultHandler) BatchDeleteResults(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 {
		utils.BadRequest(c, "参数错误")
		return
	}

	if err := h.resultService.BatchDeleteResults(req.IDs); err != nil {
		utils.Error(c, 500, "删除失败: "+err.Error())
		return
	}

	utils.SuccessWithMessage(c, "删除成功", nil)
}
