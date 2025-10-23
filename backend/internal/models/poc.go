package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PoC PoC模型
type PoC struct {
	ID           string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name         string         `gorm:"type:varchar(255);not null;index" json:"name"`
	Category     string         `gorm:"type:varchar(200);not null;index" json:"category"` // 扩展到200，支持更长的分类名
	Severity     string         `gorm:"type:varchar(100);not null" json:"severity"`       // critical, high, medium, low, info
	CVE          string         `gorm:"type:varchar(100);index" json:"cve"`               // 扩展到100，支持带描述的CVE
	Author       string         `gorm:"type:varchar(100)" json:"author"`
	Description  string         `gorm:"type:text" json:"description"`
	Reference    string         `gorm:"type:text" json:"reference"`
	PoCType      string         `gorm:"type:varchar(100);not null" json:"poc_type"` // nuclei, xray, custom
	PoCContent   string         `gorm:"type:text;not null" json:"poc_content"`
	Tags         string         `gorm:"type:varchar(500)" json:"tags"`                      // 逗号分隔的标签
	Fingerprints string         `gorm:"type:varchar(1000)" json:"fingerprints"`             // 关联的指纹名称,逗号分隔,用于智能匹配
	AppNames     string         `gorm:"type:varchar(1000);index" json:"app_names"`          // 应用名称关键词,逗号分隔
	MatchMode    string         `gorm:"type:varchar(20);default:'fuzzy'" json:"match_mode"` // 匹配模式: exact(精确), fuzzy(模糊), keyword(关键词)
	IsEnabled    bool           `gorm:"default:true" json:"is_enabled"`
	CreatedBy    string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (PoC) TableName() string {
	return "pocs"
}

// BeforeCreate 创建前钩子
func (p *PoC) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}

// PoCExecutionLog PoC执行日志
type PoCExecutionLog struct {
	ID        string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	PoCID     string    `gorm:"type:varchar(36);not null;index" json:"poc_id"`
	TaskID    string    `gorm:"type:varchar(36);index" json:"task_id"`
	Target    string    `gorm:"type:varchar(500);not null" json:"target"`
	Result    string    `gorm:"type:varchar(50);not null" json:"result"` // vulnerable, safe, error
	Details   string    `gorm:"type:text" json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName 指定表名
func (PoCExecutionLog) TableName() string {
	return "poc_execution_logs"
}

// BeforeCreate 创建前钩子
func (l *PoCExecutionLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.New().String()
	}
	return nil
}
