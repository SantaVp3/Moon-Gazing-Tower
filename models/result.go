package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

	// ResultType 扫描结果类型
type ResultType string

const (
	ResultTypeSubdomain  ResultType = "subdomain"   // 子域名
	ResultTypeTakeover   ResultType = "takeover"    // 子域名接管
	ResultTypeApp        ResultType = "app"         // APP
	ResultTypeMiniApp    ResultType = "miniapp"     // 小程序
	ResultTypeURL        ResultType = "url"         // URL
	ResultTypeCrawler    ResultType = "crawler"     // 爬虫
	ResultTypeSensitive  ResultType = "sensitive"   // 敏感信息
	ResultTypeDirScan    ResultType = "dirscan"     // 目录扫描
	ResultTypeVuln       ResultType = "vuln"        // 漏洞
	ResultTypeMonitor    ResultType = "monitor"     // 页面监控
	ResultTypePort       ResultType = "port"        // 端口
	ResultTypeService    ResultType = "service"     // 服务
)

// ScanResult 扫描结果基础结构
type ScanResult struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	TaskID      primitive.ObjectID `json:"task_id" bson:"task_id"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Type        ResultType         `json:"type" bson:"type"`
	Data        bson.M             `json:"data" bson:"data"`
	Tags        []string           `json:"tags" bson:"tags"`
	Project     string             `json:"project" bson:"project"`
	Source      string             `json:"source" bson:"source"` // 来源：主动扫描/被动发现
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

// SubdomainResult 子域名结果
type SubdomainResult struct {
	Subdomain   string   `json:"subdomain" bson:"subdomain"`
	Domain      string   `json:"domain" bson:"domain"`
	IPs         []string `json:"ips" bson:"ips"`
	CDN         bool     `json:"cdn" bson:"cdn"`
	CDNProvider string   `json:"cdn_provider,omitempty" bson:"cdn_provider,omitempty"`
	Title       string   `json:"title" bson:"title"`
	StatusCode  int      `json:"status_code" bson:"status_code"`
	WebServer   string   `json:"web_server" bson:"web_server"`
	Fingerprint []string `json:"fingerprint" bson:"fingerprint"`
	IsAlive     bool     `json:"is_alive" bson:"is_alive"`
}

// TakeoverResult 子域名接管结果
type TakeoverResult struct {
	Subdomain   string `json:"subdomain" bson:"subdomain"`
	CNAME       string `json:"cname" bson:"cname"`
	Provider    string `json:"provider" bson:"provider"`       // 云服务商
	Vulnerable  bool   `json:"vulnerable" bson:"vulnerable"`
	Severity    string `json:"severity" bson:"severity"`       // high, medium, low
	Description string `json:"description" bson:"description"`
	Evidence    string `json:"evidence" bson:"evidence"`
}

// AppResult APP结果
type AppResult struct {
	Name        string   `json:"name" bson:"name"`
	Platform    string   `json:"platform" bson:"platform"` // android, ios
	PackageName string   `json:"package_name" bson:"package_name"`
	Version     string   `json:"version" bson:"version"`
	Size        int64    `json:"size" bson:"size"`
	Market      string   `json:"market" bson:"market"` // 应用市场
	DownloadURL string   `json:"download_url" bson:"download_url"`
	Permissions []string `json:"permissions" bson:"permissions"`
}

// MiniAppResult 小程序结果
type MiniAppResult struct {
	Name       string `json:"name" bson:"name"`
	AppID      string `json:"app_id" bson:"app_id"`
	Platform   string `json:"platform" bson:"platform"` // wechat, alipay, baidu
	Company    string `json:"company" bson:"company"`
	Category   string `json:"category" bson:"category"`
	QRCode     string `json:"qrcode" bson:"qrcode"`
}

// URLResult URL结果
type URLResult struct {
	URL         string   `json:"url" bson:"url"`
	Method      string   `json:"method" bson:"method"`
	StatusCode  int      `json:"status_code" bson:"status_code"`
	ContentType string   `json:"content_type" bson:"content_type"`
	Title       string   `json:"title" bson:"title"`
	Length      int      `json:"length" bson:"length"`
	Fingerprint []string `json:"fingerprint" bson:"fingerprint"`
	IsAPI       bool     `json:"is_api" bson:"is_api"`
}

// CrawlerResult 爬虫结果
type CrawlerResult struct {
	URL         string            `json:"url" bson:"url"`
	Method      string            `json:"method" bson:"method"`
	ContentType string            `json:"content_type" bson:"content_type"`
	StatusCode  int               `json:"status_code" bson:"status_code"`
	Depth       int               `json:"depth" bson:"depth"`
	Source      string            `json:"source" bson:"source"` // 来源URL
	Forms       []FormInfo        `json:"forms,omitempty" bson:"forms,omitempty"`
	Links       []string          `json:"links,omitempty" bson:"links,omitempty"`
	JSFiles     []string          `json:"js_files,omitempty" bson:"js_files,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty" bson:"parameters,omitempty"`
}

// FormInfo 表单信息
type FormInfo struct {
	Action  string   `json:"action" bson:"action"`
	Method  string   `json:"method" bson:"method"`
	Inputs  []string `json:"inputs" bson:"inputs"`
}

// SensitiveResult 敏感信息结果
type SensitiveResult struct {
	URL         string `json:"url" bson:"url"`
	Type        string `json:"type" bson:"type"`     // email, phone, idcard, apikey, password, etc.
	Value       string `json:"value" bson:"value"`
	Context     string `json:"context" bson:"context"` // 上下文
	Location    string `json:"location" bson:"location"` // body, header, js, etc.
	Severity    string `json:"severity" bson:"severity"`
}

// DirScanResult 目录扫描结果
type DirScanResult struct {
	URL         string `json:"url" bson:"url"`
	Path        string `json:"path" bson:"path"`
	StatusCode  int    `json:"status_code" bson:"status_code"`
	ContentType string `json:"content_type" bson:"content_type"`
	Length      int    `json:"length" bson:"length"`
	Redirect    string `json:"redirect,omitempty" bson:"redirect,omitempty"`
	IsBackup    bool   `json:"is_backup" bson:"is_backup"`
	IsConfig    bool   `json:"is_config" bson:"is_config"`
}

// MonitorResult 页面监控结果
type MonitorResult struct {
	URL         string    `json:"url" bson:"url"`
	Title       string    `json:"title" bson:"title"`
	Hash        string    `json:"hash" bson:"hash"`         // 内容hash
	Screenshot  string    `json:"screenshot" bson:"screenshot"` // 截图路径
	StatusCode  int       `json:"status_code" bson:"status_code"`
	Changed     bool      `json:"changed" bson:"changed"`
	ChangeType  string    `json:"change_type" bson:"change_type"` // content, title, status
	LastCheck   time.Time `json:"last_check" bson:"last_check"`
}

// PortResult 端口扫描结果
type PortResult struct {
	IP          string   `json:"ip" bson:"ip"`
	Port        int      `json:"port" bson:"port"`
	Protocol    string   `json:"protocol" bson:"protocol"` // tcp, udp
	State       string   `json:"state" bson:"state"`       // open, closed, filtered
	Service     string   `json:"service" bson:"service"`
	Version     string   `json:"version" bson:"version"`
	Banner      string   `json:"banner" bson:"banner"`
	Fingerprint []string `json:"fingerprint" bson:"fingerprint"`
}

// Collection names for results
const (
	CollectionScanResults = "scan_results"
)
