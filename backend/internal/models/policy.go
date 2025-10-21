package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Policy 策略配置模型
type Policy struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	Config      PolicyConfig   `gorm:"embedded;embeddedPrefix:config_" json:"config"`
	IsDefault   bool           `gorm:"default:false" json:"is_default"`
	CreatedBy   string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// PolicyConfig 策略配置详情
type PolicyConfig struct {
	// 域名爆破配置
	DomainBruteType   string `json:"domain_brute_type"`   // big, test
	EnableDomainBrute bool   `json:"enable_domain_brute"`
	SmartDictGen      bool   `json:"smart_dict_gen"`

	// 端口扫描配置
	PortScanType   string `json:"port_scan_type"` // all, top1000, top100, test
	EnablePortScan bool   `json:"enable_port_scan"`

	// 服务识别配置
	EnableServiceDetect bool `json:"enable_service_detect"`
	EnableOSDetect      bool `json:"enable_os_detect"`
	EnableSSLCert       bool `json:"enable_ssl_cert"`

	// 域名查询插件
	EnableDomainPlugins bool     `json:"enable_domain_plugins"`
	DomainPlugins       []string `gorm:"type:text;serializer:json" json:"domain_plugins"` // 插件列表

	// ARL历史查询
	EnableARLHistory bool `json:"enable_arl_history"`

	// CDN
	SkipCDN bool `json:"skip_cdn"`

	// 站点识别
	EnableSiteDetect   bool `json:"enable_site_detect"`
	EnableSearchEngine bool `json:"enable_search_engine"`
	EnableCrawler      bool `json:"enable_crawler"`
	EnableScreenshot   bool `json:"enable_screenshot"`

	// 风险检测
	EnableFileLeak      bool `json:"enable_file_leak"`
	EnableHostCollision bool `json:"enable_host_collision"`

	// 高级功能
	EnablePoCDetection bool `json:"enable_poc_detection"` // 智能PoC检测
	EnableWIH          bool `json:"enable_wih"`
}

// TableName 指定表名
func (Policy) TableName() string {
	return "policies"
}

// BeforeCreate 创建前钩子
func (p *Policy) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}

