package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Setting 系统设置模型
type Setting struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Category    string         `gorm:"type:varchar(50);not null;index" json:"category"` // api, notification, scanner, dictionary
	Key         string         `gorm:"type:varchar(100);not null;uniqueIndex" json:"key"`
	Value       string         `gorm:"type:text" json:"value"`
	Description string         `gorm:"type:varchar(255)" json:"description"`
	IsEncrypted bool           `gorm:"default:false" json:"is_encrypted"` // 是否加密存储（API Key等）
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (Setting) TableName() string {
	return "settings"
}

// BeforeCreate 创建前钩子
func (s *Setting) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

// Dictionary 字典模型
type Dictionary struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(100);not null" json:"name"`
	Type        string         `gorm:"type:varchar(50);not null" json:"type"` // domain, port, file_leak
	FilePath    string         `gorm:"type:varchar(255);not null" json:"file_path"`
	Size        int64          `json:"size"`        // 文件大小（字节）
	LineCount   int            `json:"line_count"`  // 行数
	IsDefault   bool           `gorm:"default:false" json:"is_default"`
	Description string         `gorm:"type:text" json:"description"`
	CreatedBy   string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (Dictionary) TableName() string {
	return "dictionaries"
}

// BeforeCreate 创建前钩子
func (d *Dictionary) BeforeCreate(tx *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}

// SettingCategory 设置分类常量
const (
	SettingCategoryAPI          = "api"
	SettingCategoryNotification = "notification"
	SettingCategoryScanner      = "scanner"
	SettingCategoryDictionary   = "dictionary"
	SettingCategorySecurity     = "security"
)

// 默认设置键名
const (
	// API配置
	SettingKeyFOFAEmail      = "fofa_email"
	SettingKeyFOFAKey        = "fofa_key"
	SettingKeyHunterKey      = "hunter_api_key"
	SettingKeyGitHubToken    = "github_token"
	SettingKeyShodanKey      = "shodan_api_key"
	SettingKeyVirusTotalKey  = "virustotal_api_key"

	// 通知配置
	SettingKeyDingDingEnabled  = "dingding_enabled"
	SettingKeyDingDingWebhook  = "dingding_webhook"
	SettingKeyDingDingSecret   = "dingding_secret"
	SettingKeyFeishuEnabled    = "feishu_enabled"
	SettingKeyFeishuWebhook    = "feishu_webhook"
	SettingKeyEmailEnabled     = "email_enabled"
	SettingKeyEmailSMTPServer  = "email_smtp_server"
	SettingKeyEmailSMTPPort    = "email_smtp_port"
	SettingKeyEmailUsername    = "email_username"
	SettingKeyEmailPassword    = "email_password"
	SettingKeyEmailFrom        = "email_from"

	// 扫描器配置
	SettingKeyDomainBruteConcurrent = "domain_brute_concurrent"
	SettingKeyPortScanConcurrent    = "port_scan_concurrent"
	SettingKeySiteDetectConcurrent  = "site_detect_concurrent"

	// 安全配置
	SettingKeyBlackIPs     = "black_ips"
	SettingKeyBlackDomains = "black_domains"
)

