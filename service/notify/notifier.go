package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// NotifyType 通知类型
type NotifyType string

const (
	NotifyTypeDingTalk NotifyType = "dingtalk"
	NotifyTypeFeishu   NotifyType = "feishu"
	NotifyTypeWechat   NotifyType = "wechat"
	NotifyTypeEmail    NotifyType = "email"
	NotifyTypeWebhook  NotifyType = "webhook"
)

// NotifyLevel 通知级别
type NotifyLevel string

const (
	NotifyLevelInfo     NotifyLevel = "info"
	NotifyLevelWarning  NotifyLevel = "warning"
	NotifyLevelCritical NotifyLevel = "critical"
)

// NotifyMessage 通知消息
type NotifyMessage struct {
	Level     NotifyLevel            `json:"level"`
	Title     string                 `json:"title"`
	Content   string                 `json:"content"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"` // 来源模块
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// NotifyConfig 通知配置
type NotifyConfig struct {
	Type      NotifyType `json:"type"`
	Enabled   bool       `json:"enabled"`
	Name      string     `json:"name"`
	
	// DingTalk
	DingTalkWebhook string `json:"dingtalk_webhook,omitempty"`
	DingTalkSecret  string `json:"dingtalk_secret,omitempty"`
	
	// Feishu
	FeishuWebhook string `json:"feishu_webhook,omitempty"`
	FeishuSecret  string `json:"feishu_secret,omitempty"`
	
	// WeChat Work
	WechatWebhook string `json:"wechat_webhook,omitempty"`
	
	// Email
	SMTPHost     string   `json:"smtp_host,omitempty"`
	SMTPPort     int      `json:"smtp_port,omitempty"`
	SMTPUser     string   `json:"smtp_user,omitempty"`
	SMTPPassword string   `json:"smtp_password,omitempty"`
	SMTPFrom     string   `json:"smtp_from,omitempty"`
	EmailTo      []string `json:"email_to,omitempty"`
	
	// Custom Webhook
	WebhookURL     string            `json:"webhook_url,omitempty"`
	WebhookMethod  string            `json:"webhook_method,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`
}

// Notifier 通知器接口
type Notifier interface {
	Send(ctx context.Context, msg *NotifyMessage) error
	Type() NotifyType
}

// DingTalkNotifier 钉钉通知
type DingTalkNotifier struct {
	webhook string
	secret  string
	client  *http.Client
}

// NewDingTalkNotifier 创建钉钉通知器
func NewDingTalkNotifier(webhook, secret string) *DingTalkNotifier {
	return &DingTalkNotifier{
		webhook: webhook,
		secret:  secret,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *DingTalkNotifier) Type() NotifyType {
	return NotifyTypeDingTalk
}

func (n *DingTalkNotifier) Send(ctx context.Context, msg *NotifyMessage) error {
	webhook := n.webhook
	
	// 如果有签名密钥，添加签名
	if n.secret != "" {
		timestamp := time.Now().UnixMilli()
		sign := n.sign(timestamp)
		webhook = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhook, timestamp, url.QueryEscape(sign))
	}
	
	// 构建消息
	content := fmt.Sprintf("## %s\n\n**级别**: %s\n**来源**: %s\n**时间**: %s\n\n%s",
		msg.Title, msg.Level, msg.Source, msg.Timestamp.Format("2006-01-02 15:04:05"), msg.Content)
	
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": msg.Title,
			"text":  content,
		},
	}
	
	return n.post(ctx, webhook, payload)
}

func (n *DingTalkNotifier) sign(timestamp int64) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, n.secret)
	h := hmac.New(sha256.New, []byte(n.secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (n *DingTalkNotifier) post(ctx context.Context, url string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dingtalk error: %s", string(respBody))
	}
	
	return nil
}

// FeishuNotifier 飞书通知
type FeishuNotifier struct {
	webhook string
	secret  string
	client  *http.Client
}

// NewFeishuNotifier 创建飞书通知器
func NewFeishuNotifier(webhook, secret string) *FeishuNotifier {
	return &FeishuNotifier{
		webhook: webhook,
		secret:  secret,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *FeishuNotifier) Type() NotifyType {
	return NotifyTypeFeishu
}

func (n *FeishuNotifier) Send(ctx context.Context, msg *NotifyMessage) error {
	timestamp := time.Now().Unix()
	
	// 构建消息
	payload := map[string]interface{}{
		"msg_type": "interactive",
		"card": map[string]interface{}{
			"header": map[string]interface{}{
				"title": map[string]string{
					"tag":     "plain_text",
					"content": msg.Title,
				},
				"template": n.getColorByLevel(msg.Level),
			},
			"elements": []map[string]interface{}{
				{
					"tag": "div",
					"fields": []map[string]interface{}{
						{
							"is_short": true,
							"text": map[string]string{
								"tag":     "lark_md",
								"content": fmt.Sprintf("**级别**\n%s", msg.Level),
							},
						},
						{
							"is_short": true,
							"text": map[string]string{
								"tag":     "lark_md",
								"content": fmt.Sprintf("**来源**\n%s", msg.Source),
							},
						},
					},
				},
				{
					"tag": "div",
					"text": map[string]string{
						"tag":     "lark_md",
						"content": msg.Content,
					},
				},
				{
					"tag": "note",
					"elements": []map[string]string{
						{
							"tag":     "plain_text",
							"content": msg.Timestamp.Format("2006-01-02 15:04:05"),
						},
					},
				},
			},
		},
	}
	
	// 如果有签名密钥
	if n.secret != "" {
		sign := n.sign(timestamp)
		payload["timestamp"] = fmt.Sprintf("%d", timestamp)
		payload["sign"] = sign
	}
	
	return n.post(ctx, n.webhook, payload)
}

func (n *FeishuNotifier) getColorByLevel(level NotifyLevel) string {
	switch level {
	case NotifyLevelCritical:
		return "red"
	case NotifyLevelWarning:
		return "orange"
	default:
		return "blue"
	}
}

func (n *FeishuNotifier) sign(timestamp int64) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, n.secret)
	h := hmac.New(sha256.New, []byte(stringToSign))
	h.Write([]byte{})
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (n *FeishuNotifier) post(ctx context.Context, url string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("feishu error: %s", string(respBody))
	}
	
	return nil
}

// WechatNotifier 企业微信通知
type WechatNotifier struct {
	webhook string
	client  *http.Client
}

// NewWechatNotifier 创建企业微信通知器
func NewWechatNotifier(webhook string) *WechatNotifier {
	return &WechatNotifier{
		webhook: webhook,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *WechatNotifier) Type() NotifyType {
	return NotifyTypeWechat
}

func (n *WechatNotifier) Send(ctx context.Context, msg *NotifyMessage) error {
	content := fmt.Sprintf("## %s\n> 级别: <font color=\"%s\">%s</font>\n> 来源: %s\n> 时间: %s\n\n%s",
		msg.Title, n.getColorByLevel(msg.Level), msg.Level, msg.Source, 
		msg.Timestamp.Format("2006-01-02 15:04:05"), msg.Content)
	
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": content,
		},
	}
	
	return n.post(ctx, n.webhook, payload)
}

func (n *WechatNotifier) getColorByLevel(level NotifyLevel) string {
	switch level {
	case NotifyLevelCritical:
		return "warning"
	case NotifyLevelWarning:
		return "comment"
	default:
		return "info"
	}
}

func (n *WechatNotifier) post(ctx context.Context, url string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("wechat error: %s", string(respBody))
	}
	
	return nil
}

// WebhookNotifier 自定义 Webhook 通知
type WebhookNotifier struct {
	url     string
	method  string
	headers map[string]string
	client  *http.Client
}

// NewWebhookNotifier 创建自定义 Webhook 通知器
func NewWebhookNotifier(webhookURL, method string, headers map[string]string) *WebhookNotifier {
	if method == "" {
		method = "POST"
	}
	return &WebhookNotifier{
		url:     webhookURL,
		method:  method,
		headers: headers,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *WebhookNotifier) Type() NotifyType {
	return NotifyTypeWebhook
}

func (n *WebhookNotifier) Send(ctx context.Context, msg *NotifyMessage) error {
	payload := map[string]interface{}{
		"level":     msg.Level,
		"title":     msg.Title,
		"content":   msg.Content,
		"source":    msg.Source,
		"timestamp": msg.Timestamp.Unix(),
		"extra":     msg.Extra,
	}
	
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, n.method, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	for k, v := range n.headers {
		req.Header.Set(k, v)
	}
	
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook error: status=%d, body=%s", resp.StatusCode, string(respBody))
	}
	
	return nil
}
