package api

import (
	"moongazing/service/notify"
	"moongazing/utils"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// NotifyHandler 通知处理器
type NotifyHandler struct {
	manager *notify.NotifyManager
}

// NewNotifyHandler 创建通知处理器
func NewNotifyHandler() *NotifyHandler {
	// 使用全局通知管理器
	manager := notify.GetGlobalManager()
	return &NotifyHandler{
		manager: manager,
	}
}

// GetManager 获取通知管理器
func (h *NotifyHandler) GetManager() *notify.NotifyManager {
	return h.manager
}

// GetConfigs 获取所有通知配置
// @Summary 获取通知配置列表
// @Tags Notify
// @Security ApiKeyAuth
// @Success 200 {object} Response
// @Router /api/notify/configs [get]
func (h *NotifyHandler) GetConfigs(c *gin.Context) {
	configs := h.manager.GetConfigs()
	
	// 隐藏敏感信息
	for i := range configs {
		configs[i].DingTalkSecret = maskSecret(configs[i].DingTalkSecret)
		configs[i].FeishuSecret = maskSecret(configs[i].FeishuSecret)
		configs[i].SMTPPassword = maskSecret(configs[i].SMTPPassword)
	}
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "success",
		Data:    configs,
	})
}

// AddConfig 添加通知配置
// @Summary 添加通知配置
// @Tags Notify
// @Security ApiKeyAuth
// @Param config body notify.NotifyConfig true "通知配置"
// @Success 200 {object} Response
// @Router /api/notify/configs [post]
func (h *NotifyHandler) AddConfig(c *gin.Context) {
	var config notify.NotifyConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}
	
	if config.Name == "" {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Name is required",
		})
		return
	}
	
	h.manager.AddConfig(config)
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "Config added successfully",
	})
}

// UpdateConfig 更新通知配置
// @Summary 更新通知配置
// @Tags Notify
// @Security ApiKeyAuth
// @Param config body notify.NotifyConfig true "通知配置"
// @Success 200 {object} Response
// @Router /api/notify/configs [put]
func (h *NotifyHandler) UpdateConfig(c *gin.Context) {
	var config notify.NotifyConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}
	
	h.manager.AddConfig(config)
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "Config updated successfully",
	})
}

// DeleteConfig 删除通知配置
// @Summary 删除通知配置
// @Tags Notify
// @Security ApiKeyAuth
// @Param name query string true "配置名称"
// @Param type query string true "通知类型"
// @Success 200 {object} Response
// @Router /api/notify/configs [delete]
func (h *NotifyHandler) DeleteConfig(c *gin.Context) {
	name := c.Query("name")
	notifyType := c.Query("type")
	
	if name == "" || notifyType == "" {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Name and type are required",
		})
		return
	}
	
	h.manager.RemoveConfig(name, notify.NotifyType(notifyType))
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "Config deleted successfully",
	})
}

// EnableConfig 启用/禁用通知配置
// @Summary 启用/禁用通知配置
// @Tags Notify
// @Security ApiKeyAuth
// @Param request body EnableConfigRequest true "启用请求"
// @Success 200 {object} Response
// @Router /api/notify/configs/enable [post]
func (h *NotifyHandler) EnableConfig(c *gin.Context) {
	var req struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}
	
	h.manager.EnableConfig(req.Name, notify.NotifyType(req.Type), req.Enabled)
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "Config updated successfully",
	})
}

// TestConfig 测试通知配置
// @Summary 测试通知配置
// @Tags Notify
// @Security ApiKeyAuth
// @Param config body notify.NotifyConfig true "通知配置"
// @Success 200 {object} Response
// @Router /api/notify/test [post]
func (h *NotifyHandler) TestConfig(c *gin.Context) {
	var config notify.NotifyConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}
	
	config.Enabled = true // 测试时强制启用
	
	if err := h.manager.TestNotifier(config); err != nil {
		c.JSON(http.StatusOK, utils.Response{
			Code:    -1,
			Message: "Test failed: " + err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "Test notification sent successfully",
	})
}

// SendNotification 手动发送通知
// @Summary 手动发送通知
// @Tags Notify
// @Security ApiKeyAuth
// @Param message body notify.NotifyMessage true "通知消息"
// @Success 200 {object} Response
// @Router /api/notify/send [post]
func (h *NotifyHandler) SendNotification(c *gin.Context) {
	var msg notify.NotifyMessage
	if err := c.ShouldBindJSON(&msg); err != nil {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Invalid request: " + err.Error(),
		})
		return
	}
	
	if msg.Title == "" {
		c.JSON(http.StatusBadRequest, utils.Response{
			Code:    -1,
			Message: "Title is required",
		})
		return
	}
	
	if msg.Source == "" {
		msg.Source = "manual"
	}
	
	if msg.Level == "" {
		msg.Level = notify.NotifyLevelInfo
	}
	
	if err := h.manager.Send(c.Request.Context(), &msg); err != nil {
		c.JSON(http.StatusOK, utils.Response{
			Code:    -1,
			Message: "Failed to send notification: " + err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "Notification sent successfully",
	})
}

// GetHistory 获取通知历史
// @Summary 获取通知历史
// @Tags Notify
// @Security ApiKeyAuth
// @Param limit query int false "返回数量限制"
// @Success 200 {object} Response
// @Router /api/notify/history [get]
func (h *NotifyHandler) GetHistory(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)
	
	history := h.manager.GetHistory(limit)
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "success",
		Data:    history,
	})
}

// GetSupportedTypes 获取支持的通知类型
// @Summary 获取支持的通知类型
// @Tags Notify
// @Security ApiKeyAuth
// @Success 200 {object} Response
// @Router /api/notify/types [get]
func (h *NotifyHandler) GetSupportedTypes(c *gin.Context) {
	types := []map[string]interface{}{
		{
			"type":        "dingtalk",
			"name":        "钉钉机器人",
			"description": "通过钉钉群机器人 Webhook 发送通知",
			"fields": []map[string]string{
				{"key": "dingtalk_webhook", "label": "Webhook URL", "type": "text", "required": "true"},
				{"key": "dingtalk_secret", "label": "签名密钥", "type": "password", "required": "false"},
			},
		},
		{
			"type":        "feishu",
			"name":        "飞书机器人",
			"description": "通过飞书群机器人 Webhook 发送通知",
			"fields": []map[string]string{
				{"key": "feishu_webhook", "label": "Webhook URL", "type": "text", "required": "true"},
				{"key": "feishu_secret", "label": "签名密钥", "type": "password", "required": "false"},
			},
		},
		{
			"type":        "wechat",
			"name":        "企业微信",
			"description": "通过企业微信群机器人 Webhook 发送通知",
			"fields": []map[string]string{
				{"key": "wechat_webhook", "label": "Webhook URL", "type": "text", "required": "true"},
			},
		},
		{
			"type":        "email",
			"name":        "邮件通知",
			"description": "通过 SMTP 发送邮件通知",
			"fields": []map[string]string{
				{"key": "smtp_host", "label": "SMTP 服务器", "type": "text", "required": "true"},
				{"key": "smtp_port", "label": "SMTP 端口", "type": "number", "required": "true"},
				{"key": "smtp_user", "label": "用户名", "type": "text", "required": "true"},
				{"key": "smtp_password", "label": "密码", "type": "password", "required": "true"},
				{"key": "smtp_from", "label": "发件人地址", "type": "text", "required": "true"},
				{"key": "email_to", "label": "收件人地址(多个用逗号分隔)", "type": "text", "required": "true"},
			},
		},
		{
			"type":        "webhook",
			"name":        "自定义 Webhook",
			"description": "发送 JSON 数据到自定义 HTTP 端点",
			"fields": []map[string]string{
				{"key": "webhook_url", "label": "Webhook URL", "type": "text", "required": "true"},
				{"key": "webhook_method", "label": "HTTP 方法", "type": "select", "required": "false"},
				{"key": "webhook_headers", "label": "自定义 Headers (JSON)", "type": "textarea", "required": "false"},
			},
		},
	}
	
	c.JSON(http.StatusOK, utils.Response{
		Code:    0,
		Message: "success",
		Data:    types,
	})
}

// maskSecret 隐藏敏感信息
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
