package api

import (
	"moongazing/service/monitor"
	"moongazing/service/notify"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

// MonitorHandler 页面监控处理器
type MonitorHandler struct {
	pageMonitor   *monitor.PageMonitor
	notifyManager *notify.NotifyManager
	changes       []*monitor.PageChange
}

// NewMonitorHandler 创建监控处理器
func NewMonitorHandler(notifyManager *notify.NotifyManager) *MonitorHandler {
	pageMonitor := monitor.NewPageMonitor()
	
	h := &MonitorHandler{
		pageMonitor:   pageMonitor,
		notifyManager: notifyManager,
		changes:       make([]*monitor.PageChange, 0),
	}
	
	// 设置变化回调
	pageMonitor.SetChangeCallback(func(change *monitor.PageChange) {
		h.onPageChange(change)
	})
	
	return h
}

// onPageChange 页面变化回调
func (h *MonitorHandler) onPageChange(change *monitor.PageChange) {
	// 存储变化记录
	h.changes = append(h.changes, change)
	if len(h.changes) > 1000 {
		h.changes = h.changes[len(h.changes)-1000:]
	}
	
	// 发送通知
	if h.notifyManager != nil {
		msg := &notify.NotifyMessage{
			Level:     notify.NotifyLevelWarning,
			Title:     "页面内容变化检测",
			Content:   formatChangeContent(change),
			Source:    "page_monitor",
			Timestamp: change.Timestamp,
		}
		h.notifyManager.SendAsync(msg)
	}
}

func formatChangeContent(change *monitor.PageChange) string {
	content := "**URL**: " + change.URL + "\n"
	content += "**变化类型**: " + change.ChangeType + "\n"
	
	switch change.ChangeType {
	case "status":
		content += "**状态码变化**: " + string(rune(change.OldStatus)) + " → " + string(rune(change.NewStatus))
	case "title":
		content += "**旧标题**: " + change.OldContent + "\n"
		content += "**新标题**: " + change.NewContent
	default:
		if change.OldContent != "" {
			content += "**旧内容**: " + truncateStr(change.OldContent, 200) + "\n"
		}
		if change.NewContent != "" {
			content += "**新内容**: " + truncateStr(change.NewContent, 200)
		}
	}
	
	return content
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ListMonitoredPages 获取所有监控页面
// @Summary 获取监控页面列表
// @Tags Monitor
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/monitor/pages [get]
func (h *MonitorHandler) ListMonitoredPages(c *gin.Context) {
	pages := h.pageMonitor.GetAllPages()
	
	// 简化输出
	items := make([]map[string]interface{}, len(pages))
	for i, p := range pages {
		items[i] = map[string]interface{}{
			"id":           p.ID,
			"url":          p.URL,
			"name":         p.Name,
			"interval":     p.Interval.Seconds(),
			"monitor_type": p.MonitorType,
			"enabled":      p.Enabled,
			"last_check":   p.LastCheck,
			"last_status":  p.LastStatus,
			"change_count": p.ChangeCount,
			"error_count":  p.ErrorCount,
			"last_error":   p.LastError,
		}
	}
	
	utils.Success(c, items)
}

// GetMonitoredPage 获取单个监控页面详情
// @Summary 获取监控页面详情
// @Tags Monitor
// @Security ApiKeyAuth
// @Param id path string true "页面ID"
// @Success 200 {object} utils.Response
// @Router /api/monitor/pages/{id} [get]
func (h *MonitorHandler) GetMonitoredPage(c *gin.Context) {
	id := c.Param("id")
	
	page, ok := h.pageMonitor.GetPage(id)
	if !ok {
		utils.NotFound(c, "页面不存在")
		return
	}
	
	utils.Success(c, page)
}

// AddMonitoredPage 添加监控页面
// @Summary 添加监控页面
// @Tags Monitor
// @Security ApiKeyAuth
// @Param config body monitor.MonitorConfig true "监控配置"
// @Success 200 {object} utils.Response
// @Router /api/monitor/pages [post]
func (h *MonitorHandler) AddMonitoredPage(c *gin.Context) {
	var config monitor.MonitorConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	page, err := h.pageMonitor.AddPage(config)
	if err != nil {
		utils.BadRequest(c, "添加失败: "+err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "添加成功", map[string]interface{}{
		"id":  page.ID,
		"url": page.URL,
	})
}

// RemoveMonitoredPage 移除监控页面
// @Summary 移除监控页面
// @Tags Monitor
// @Security ApiKeyAuth
// @Param id path string true "页面ID"
// @Success 200 {object} utils.Response
// @Router /api/monitor/pages/{id} [delete]
func (h *MonitorHandler) RemoveMonitoredPage(c *gin.Context) {
	id := c.Param("id")
	
	if err := h.pageMonitor.RemovePage(id); err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// EnableMonitoredPage 启用/禁用监控
// @Summary 启用/禁用页面监控
// @Tags Monitor
// @Security ApiKeyAuth
// @Param id path string true "页面ID"
// @Param enabled body bool true "是否启用"
// @Success 200 {object} utils.Response
// @Router /api/monitor/pages/{id}/enable [put]
func (h *MonitorHandler) EnableMonitoredPage(c *gin.Context) {
	id := c.Param("id")
	
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.pageMonitor.EnablePage(id, req.Enabled); err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// CheckPageNow 立即检查页面
// @Summary 立即检查页面
// @Tags Monitor
// @Security ApiKeyAuth
// @Param id path string true "页面ID"
// @Success 200 {object} utils.Response
// @Router /api/monitor/pages/{id}/check [post]
func (h *MonitorHandler) CheckPageNow(c *gin.Context) {
	id := c.Param("id")
	
	change, err := h.pageMonitor.CheckNow(id)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	result := map[string]interface{}{
		"changed": change != nil,
	}
	
	if change != nil {
		result["change"] = change
	}
	
	utils.Success(c, result)
}

// GetChanges 获取变化历史
// @Summary 获取页面变化历史
// @Tags Monitor
// @Security ApiKeyAuth
// @Param page_id query string false "页面ID过滤"
// @Param limit query int false "返回数量"
// @Success 200 {object} utils.Response
// @Router /api/monitor/changes [get]
func (h *MonitorHandler) GetChanges(c *gin.Context) {
	pageID := c.Query("page_id")
	
	changes := h.changes
	
	// 按页面过滤
	if pageID != "" {
		filtered := make([]*monitor.PageChange, 0)
		for _, ch := range changes {
			if ch.PageID == pageID {
				filtered = append(filtered, ch)
			}
		}
		changes = filtered
	}
	
	// 反转顺序，最新的在前
	reversed := make([]*monitor.PageChange, len(changes))
	for i, ch := range changes {
		reversed[len(changes)-1-i] = ch
	}
	
	utils.Success(c, reversed)
}

// GetMonitorTypes 获取支持的监控类型
// @Summary 获取支持的监控类型
// @Tags Monitor
// @Security ApiKeyAuth
// @Success 200 {object} utils.Response
// @Router /api/monitor/types [get]
func (h *MonitorHandler) GetMonitorTypes(c *gin.Context) {
	types := []map[string]interface{}{
		{
			"type":        "full_page",
			"name":        "完整页面",
			"description": "监控整个页面的文本内容变化",
		},
		{
			"type":        "selector",
			"name":        "CSS选择器",
			"description": "监控指定 CSS 选择器匹配的元素内容",
		},
		{
			"type":        "keyword",
			"name":        "关键词",
			"description": "监控指定关键词的出现或消失",
		},
		{
			"type":        "status",
			"name":        "状态码",
			"description": "监控 HTTP 响应状态码变化",
		},
		{
			"type":        "hash",
			"name":        "内容哈希",
			"description": "监控页面原始内容的哈希值变化",
		},
		{
			"type":        "title",
			"name":        "页面标题",
			"description": "监控页面标题变化",
		},
	}
	
	utils.Success(c, types)
}

// GetPageMonitor 获取监控器实例
func (h *MonitorHandler) GetPageMonitor() *monitor.PageMonitor {
	return h.pageMonitor
}
