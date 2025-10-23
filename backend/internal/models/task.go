package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// Task 任务模型
type Task struct {
	ID           string      `gorm:"primaryKey;type:uuid" json:"id"`
	Name         string      `gorm:"type:varchar(255);not null" json:"name"`
	Target       string      `gorm:"type:text;not null" json:"target"`                  // IP, IP段或域名，多个用逗号分隔
	PolicyID     string      `gorm:"type:varchar(36);index" json:"policy_id,omitempty"` // 关联的策略ID
	Status       TaskStatus  `gorm:"type:varchar(50);default:'pending'" json:"status"`
	Options      TaskOptions `gorm:"embedded;embeddedPrefix:opt_" json:"options"`
	Progress     int         `gorm:"default:0" json:"progress"`                // 0-100
	AssetProfile string      `gorm:"type:text" json:"asset_profile,omitempty"` // 资产画像JSON
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
	StartedAt    *time.Time  `json:"started_at,omitempty"`
	EndedAt      *time.Time  `json:"ended_at,omitempty"`
	ErrorMsg     string      `gorm:"type:text" json:"error_msg,omitempty"`
}

// TaskOptions 任务选项
type TaskOptions struct {
	// 目标
	Target string `json:"target"` // IP, IP段或域名，多个用逗号分隔

	// 域名爆破
	DomainBruteType   string `json:"domain_brute_type"` // big, test
	EnableDomainBrute bool   `json:"enable_domain_brute"`
	SmartDictGen      bool   `json:"smart_dict_gen"`

	// 端口扫描
	PortScanType   string `json:"port_scan_type"` // all, top1000, top100, test
	EnablePortScan bool   `json:"enable_port_scan"`
	EnableCSegment bool   `json:"enable_c_segment"` // 启用C段扫描

	// 服务识别
	EnableServiceDetect bool `json:"enable_service_detect"`
	EnableOSDetect      bool `json:"enable_os_detect"`
	EnableSSLCert       bool `json:"enable_ssl_cert"`

	// 域名查询插件
	EnableDomainPlugins bool     `json:"enable_domain_plugins"`
	DomainPlugins       []string `gorm:"type:text;serializer:json" json:"domain_plugins"` // alienvault, certspotter, crtsh, fofa, hunter等

	// ARL历史查询
	EnableARLHistory bool `json:"enable_arl_history"`

	// CDN
	SkipCDN bool `json:"skip_cdn"`

	// 站点识别
	EnableSiteDetect   bool `json:"enable_site_detect"`
	EnableSearchEngine bool `json:"enable_search_engine"`
	EnableCrawler      bool `json:"enable_crawler"`
	CrawlerDepth       int  `json:"crawler_depth"` // 爬虫深度，默认3
	CrawlerPages       int  `json:"crawler_pages"` // 最大页面数，默认100
	EnableScreenshot   bool `json:"enable_screenshot"`

	// 风险检测
	EnableFileLeak      bool `json:"enable_file_leak"`
	EnableHostCollision bool `json:"enable_host_collision"`

	// 高级功能
	EnablePoCDetection bool   `json:"enable_poc_detection"` // 智能PoC检测(替代Nuclei/XPOC/Afrog)
	EnableCustomScript bool   `json:"enable_custom_script"`
	CustomScriptPath   string `json:"custom_script_path"`
	EnableWIH          bool   `json:"enable_wih"`

	// 被动扫描
	EnablePassiveScan bool `json:"enable_passive_scan"`
}

// BeforeCreate GORM钩子
func (t *Task) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

// TableName 指定表名
func (Task) TableName() string {
	return "tasks"
}
