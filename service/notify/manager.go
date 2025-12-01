package notify

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// 全局通知管理器实例
var (
	globalManager     *NotifyManager
	globalManagerOnce sync.Once
)

// GetGlobalManager 获取全局通知管理器实例
func GetGlobalManager() *NotifyManager {
	globalManagerOnce.Do(func() {
		globalManager = NewNotifyManager()
		globalManager.Start()
		log.Println("[Notify] Global notify manager initialized")
	})
	return globalManager
}

// NotifyManager 通知管理器
type NotifyManager struct {
	notifiers []Notifier
	configs   []NotifyConfig
	mu        sync.RWMutex
	
	// 通知队列
	queue      chan *NotifyMessage
	stopCh     chan struct{}
	
	// 通知历史
	history    []*NotifyHistory
	historyMu  sync.RWMutex
	maxHistory int
}

// NotifyHistory 通知历史记录
type NotifyHistory struct {
	ID        string      `json:"id"`
	Message   *NotifyMessage `json:"message"`
	Type      NotifyType  `json:"type"`
	Status    string      `json:"status"` // success, failed
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// NewNotifyManager 创建通知管理器
func NewNotifyManager() *NotifyManager {
	return &NotifyManager{
		notifiers:  make([]Notifier, 0),
		configs:    make([]NotifyConfig, 0),
		queue:      make(chan *NotifyMessage, 1000),
		stopCh:     make(chan struct{}),
		history:    make([]*NotifyHistory, 0),
		maxHistory: 1000,
	}
}

// Start 启动通知管理器
func (m *NotifyManager) Start() {
	go m.processQueue()
}

// Stop 停止通知管理器
func (m *NotifyManager) Stop() {
	close(m.stopCh)
}

// AddConfig 添加通知配置
func (m *NotifyManager) AddConfig(config NotifyConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// 检查是否已存在
	for i, c := range m.configs {
		if c.Name == config.Name && c.Type == config.Type {
			m.configs[i] = config
			m.rebuildNotifiers()
			return
		}
	}
	
	m.configs = append(m.configs, config)
	m.rebuildNotifiers()
}

// RemoveConfig 移除通知配置
func (m *NotifyManager) RemoveConfig(name string, t NotifyType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for i, c := range m.configs {
		if c.Name == name && c.Type == t {
			m.configs = append(m.configs[:i], m.configs[i+1:]...)
			m.rebuildNotifiers()
			return
		}
	}
}

// GetConfigs 获取所有配置
func (m *NotifyManager) GetConfigs() []NotifyConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	configs := make([]NotifyConfig, len(m.configs))
	copy(configs, m.configs)
	return configs
}

// EnableConfig 启用配置
func (m *NotifyManager) EnableConfig(name string, t NotifyType, enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for i, c := range m.configs {
		if c.Name == name && c.Type == t {
			m.configs[i].Enabled = enabled
			m.rebuildNotifiers()
			return
		}
	}
}

// rebuildNotifiers 重建通知器列表
func (m *NotifyManager) rebuildNotifiers() {
	m.notifiers = make([]Notifier, 0)
	
	for _, config := range m.configs {
		if !config.Enabled {
			continue
		}
		
		notifier := m.createNotifier(config)
		if notifier != nil {
			m.notifiers = append(m.notifiers, notifier)
		}
	}
}

// createNotifier 根据配置创建通知器
func (m *NotifyManager) createNotifier(config NotifyConfig) Notifier {
	switch config.Type {
	case NotifyTypeDingTalk:
		if config.DingTalkWebhook != "" {
			return NewDingTalkNotifier(config.DingTalkWebhook, config.DingTalkSecret)
		}
	case NotifyTypeFeishu:
		if config.FeishuWebhook != "" {
			return NewFeishuNotifier(config.FeishuWebhook, config.FeishuSecret)
		}
	case NotifyTypeWechat:
		if config.WechatWebhook != "" {
			return NewWechatNotifier(config.WechatWebhook)
		}
	case NotifyTypeEmail:
		if config.SMTPHost != "" && len(config.EmailTo) > 0 {
			return NewEmailNotifier(
				config.SMTPHost,
				config.SMTPPort,
				config.SMTPUser,
				config.SMTPPassword,
				config.SMTPFrom,
				config.EmailTo,
			)
		}
	case NotifyTypeWebhook:
		if config.WebhookURL != "" {
			return NewWebhookNotifier(config.WebhookURL, config.WebhookMethod, config.WebhookHeaders)
		}
	}
	return nil
}

// Send 发送通知（同步）
func (m *NotifyManager) Send(ctx context.Context, msg *NotifyMessage) error {
	m.mu.RLock()
	notifiers := m.notifiers
	m.mu.RUnlock()
	
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}
	
	var lastErr error
	for _, notifier := range notifiers {
		if err := notifier.Send(ctx, msg); err != nil {
			lastErr = err
			log.Printf("[Notify] Failed to send via %s: %v", notifier.Type(), err)
			m.addHistory(msg, notifier.Type(), "failed", err.Error())
		} else {
			m.addHistory(msg, notifier.Type(), "success", "")
		}
	}
	
	return lastErr
}

// SendAsync 发送通知（异步）
func (m *NotifyManager) SendAsync(msg *NotifyMessage) {
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}
	
	select {
	case m.queue <- msg:
	default:
		log.Printf("[Notify] Queue full, dropping message: %s", msg.Title)
	}
}

// processQueue 处理消息队列
func (m *NotifyManager) processQueue() {
	for {
		select {
		case <-m.stopCh:
			return
		case msg := <-m.queue:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			m.Send(ctx, msg)
			cancel()
		}
	}
}

// addHistory 添加历史记录
func (m *NotifyManager) addHistory(msg *NotifyMessage, t NotifyType, status, errMsg string) {
	m.historyMu.Lock()
	defer m.historyMu.Unlock()
	
	history := &NotifyHistory{
		ID:        generateID(),
		Message:   msg,
		Type:      t,
		Status:    status,
		Error:     errMsg,
		Timestamp: time.Now(),
	}
	
	m.history = append(m.history, history)
	
	// 限制历史记录数量
	if len(m.history) > m.maxHistory {
		m.history = m.history[len(m.history)-m.maxHistory:]
	}
}

// GetHistory 获取历史记录
func (m *NotifyManager) GetHistory(limit int) []*NotifyHistory {
	m.historyMu.RLock()
	defer m.historyMu.RUnlock()
	
	if limit <= 0 || limit > len(m.history) {
		limit = len(m.history)
	}
	
	// 返回最新的记录
	start := len(m.history) - limit
	if start < 0 {
		start = 0
	}
	
	result := make([]*NotifyHistory, limit)
	copy(result, m.history[start:])
	
	// 反转顺序，最新的在前
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	
	return result
}

// TestNotifier 测试通知器
func (m *NotifyManager) TestNotifier(config NotifyConfig) error {
	notifier := m.createNotifier(config)
	if notifier == nil {
		return nil
	}
	
	msg := &NotifyMessage{
		Level:     NotifyLevelInfo,
		Title:     "测试通知",
		Content:   "这是一条来自 Moon Gazing Tower 的测试通知消息。\n\n如果您收到此消息，说明通知配置正确。",
		Source:    "system",
		Timestamp: time.Now(),
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	return notifier.Send(ctx, msg)
}

// NotifyVulnerability 发送漏洞通知
func (m *NotifyManager) NotifyVulnerability(vulnName, target, severity, details string) {
	level := NotifyLevelInfo
	switch severity {
	case "critical", "high":
		level = NotifyLevelCritical
	case "medium":
		level = NotifyLevelWarning
	}
	
	msg := &NotifyMessage{
		Level:     level,
		Title:     "发现漏洞: " + vulnName,
		Content:   fmt.Sprintf("**目标**: %s\n**严重程度**: %s\n\n%s", target, severity, details),
		Source:    "vuln_scanner",
		Timestamp: time.Now(),
		Extra: map[string]interface{}{
			"vuln_name": vulnName,
			"target":    target,
			"severity":  severity,
		},
	}
	
	m.SendAsync(msg)
}

// NotifyTaskComplete 发送任务完成通知
func (m *NotifyManager) NotifyTaskComplete(taskName string, taskID string, success bool, summary string, stats map[string]interface{}) {
	level := NotifyLevelInfo
	title := "✅ 扫描完成: " + taskName
	if !success {
		level = NotifyLevelWarning
		title = "❌ 扫描失败: " + taskName
	}

	msg := &NotifyMessage{
		Level:     level,
		Title:     title,
		Content:   summary,
		Source:    "task_manager",
		Timestamp: time.Now(),
		Extra: map[string]interface{}{
			"task_name": taskName,
			"task_id":   taskID,
			"success":   success,
			"stats":     stats,
		},
	}

	m.SendAsync(msg)
}

// NotifyAssetChange 发送资产变更通知
func (m *NotifyManager) NotifyAssetChange(changeType, assetInfo string) {
	msg := &NotifyMessage{
		Level:     NotifyLevelInfo,
		Title:     "资产变更: " + changeType,
		Content:   assetInfo,
		Source:    "asset_monitor",
		Timestamp: time.Now(),
	}
	
	m.SendAsync(msg)
}

// generateID 生成简单ID
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
