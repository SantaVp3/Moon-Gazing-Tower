package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"moongazing/scanner/vulnscan/nuclei"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

// NucleiHandler Nuclei 处理器
type NucleiHandler struct {
	loader   *nuclei.TemplateLoader
	executor *nuclei.Executor
}

// NewNucleiHandler 创建 Nuclei 处理器
func NewNucleiHandler() *NucleiHandler {
	loader := nuclei.NewTemplateLoader()
	
	// 添加默认模板目录
	loader.AddTemplateDir("config/nuclei-templates")
	
	// 尝试加载模板
	if err := loader.LoadAll(); err != nil {
		// 忽略加载错误，可能目录不存在
	}
	
	executor := nuclei.NewExecutor(loader, nuclei.DefaultExecutorOptions())
	
	return &NucleiHandler{
		loader:   loader,
		executor: executor,
	}
}

// GetTemplates 获取模板列表
// @Summary 获取 Nuclei 模板列表
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param severity query string false "严重程度过滤"
// @Param tags query string false "标签过滤"
// @Param page query int false "页码"
// @Param size query int false "每页数量"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates [get]
func (h *NucleiHandler) GetTemplates(c *gin.Context) {
	severity := c.Query("severity")
	tags := c.Query("tags")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "20"))
	
	var templates []*nuclei.NucleiTemplate
	
	if severity != "" {
		templates = h.loader.GetTemplatesBySeverity(nuclei.Severity(severity))
	} else if tags != "" {
		templates = h.loader.GetTemplatesByTags(tags)
	} else {
		templates = h.loader.GetTemplates()
	}
	
	// 分页
	total := len(templates)
	start := (page - 1) * size
	end := start + size
	
	if start >= total {
		templates = []*nuclei.NucleiTemplate{}
	} else {
		if end > total {
			end = total
		}
		templates = templates[start:end]
	}
	
	// 简化输出
	items := make([]map[string]interface{}, len(templates))
	for i, t := range templates {
		items[i] = map[string]interface{}{
			"id":          t.ID,
			"name":        t.Info.Name,
			"author":      t.Info.Author,
			"severity":    t.Info.Severity,
			"description": t.Info.Description,
			"tags":        t.Info.Tags,
			"cve_id":      t.Info.Classification.CVEID,
			"file_path":   t.FilePath,
		}
	}
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "success",
		Data: map[string]interface{}{
			"items": items,
			"total": total,
			"page":  page,
			"size":  size,
		},
	})
}

// GetTemplate 获取单个模板详情
// @Summary 获取 Nuclei 模板详情
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param id path string true "模板ID"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates/{id} [get]
func (h *NucleiHandler) GetTemplate(c *gin.Context) {
	id := c.Param("id")
	
	template, ok := h.loader.GetTemplate(id)
	if !ok {
		utils.NotFound(c, "Template not found")
		return
	}
	
	utils.Success(c, template)
}

// GetTags 获取所有模板标签
// @Summary 获取所有 Nuclei 模板标签
// @Tags Nuclei
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/nuclei/tags [get]
func (h *NucleiHandler) GetTags(c *gin.Context) {
	tags := h.loader.GetAllTags()
	utils.Success(c, tags)
}

// GetStatistics 获取模板统计
// @Summary 获取 Nuclei 模板统计
// @Tags Nuclei
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/nuclei/statistics [get]
func (h *NucleiHandler) GetStatistics(c *gin.Context) {
	stats := h.loader.GetStatistics()
	utils.Success(c, stats)
}

// ScanTarget 扫描目标
// @Summary 使用 Nuclei 模板扫描目标
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param request body NucleiScanRequest true "扫描请求"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/scan [post]
func (h *NucleiHandler) ScanTarget(c *gin.Context) {
	var req struct {
		Target      string   `json:"target" binding:"required"`
		TemplateIDs []string `json:"template_ids,omitempty"`
		Tags        []string `json:"tags,omitempty"`
		Severity    string   `json:"severity,omitempty"`
		Timeout     int      `json:"timeout,omitempty"` // seconds
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	timeout := 120 * time.Second
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}
	
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()
	
	var results []*nuclei.ScanResult
	var err error
	
	if len(req.TemplateIDs) > 0 {
		// 指定模板扫描
		templates := make([]*nuclei.NucleiTemplate, 0)
		for _, id := range req.TemplateIDs {
			if t, ok := h.loader.GetTemplate(id); ok {
				templates = append(templates, t)
			}
		}
		results, err = h.executor.ExecuteTemplates(ctx, templates, req.Target)
	} else if len(req.Tags) > 0 {
		// 按标签扫描
		results, err = h.executor.ExecuteByTags(ctx, req.Target, req.Tags...)
	} else if req.Severity != "" {
		// 按严重程度扫描
		results, err = h.executor.ExecuteBySeverity(ctx, req.Target, nuclei.Severity(req.Severity))
	} else {
		// 全部扫描
		results, err = h.executor.ExecuteAll(ctx, req.Target)
	}
	
	if err != nil {
		utils.InternalError(c, "扫描失败: "+err.Error())
		return
	}
	
	// 过滤只返回匹配的结果
	matched := make([]*nuclei.ScanResult, 0)
	for _, r := range results {
		if r.Matched {
			matched = append(matched, r)
		}
	}
	
	utils.Success(c, map[string]interface{}{
		"target":        req.Target,
		"total_scanned": len(results),
		"matched":       len(matched),
		"results":       matched,
	})
}

// UploadTemplate 上传模板
// @Summary 上传 Nuclei 模板
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param content body string true "模板YAML内容"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates [post]
func (h *NucleiHandler) UploadTemplate(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	template, err := h.loader.Parse([]byte(req.Content), "uploaded")
	if err != nil {
		utils.BadRequest(c, "模板解析失败: "+err.Error())
		return
	}
	
	h.loader.AddTemplate(template)
	
	utils.SuccessWithMessage(c, "模板上传成功", map[string]interface{}{
		"id":       template.ID,
		"name":     template.Info.Name,
		"severity": template.Info.Severity,
	})
}

// DeleteTemplate 删除模板
// @Summary 删除 Nuclei 模板
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param id path string true "模板ID"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/templates/{id} [delete]
func (h *NucleiHandler) DeleteTemplate(c *gin.Context) {
	id := c.Param("id")
	
	if _, ok := h.loader.GetTemplate(id); !ok {
		utils.NotFound(c, "Template not found")
		return
	}
	
	h.loader.RemoveTemplate(id)
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// ReloadTemplates 重新加载模板
// @Summary 重新加载 Nuclei 模板
// @Tags Nuclei
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/nuclei/reload [post]
func (h *NucleiHandler) ReloadTemplates(c *gin.Context) {
	h.loader.Clear()
	
	if err := h.loader.LoadAll(); err != nil {
		utils.InternalError(c, "加载模板失败: "+err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "模板重新加载成功", map[string]interface{}{
		"count": h.loader.Count(),
	})
}

// ValidateTemplate 验证模板
// @Summary 验证 Nuclei 模板语法
// @Tags Nuclei
// @Security ApiKeyAuth
// @Param content body string true "模板YAML内容"
// @Success 200 {object} utils.Response
// @Router /api/nuclei/validate [post]
func (h *NucleiHandler) ValidateTemplate(c *gin.Context) {
	var req struct {
		Content string `json:"content" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	template, err := h.loader.Parse([]byte(req.Content), "validation")
	if err != nil {
		c.JSON(http.StatusOK, utils.Response{
			Code:    0,
			Message: "success",
			Data: map[string]interface{}{
				"valid":  false,
				"error":  err.Error(),
			},
		})
		return
	}
	
	utils.Success(c, map[string]interface{}{
		"valid":    true,
		"id":       template.ID,
		"name":     template.Info.Name,
		"severity": template.Info.Severity,
		"tags":     template.Info.Tags,
	})
}
