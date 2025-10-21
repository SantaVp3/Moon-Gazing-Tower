package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MonitorType 监控类型
type MonitorType string

const (
	MonitorTypeDomain MonitorType = "domain"
	MonitorTypeIP     MonitorType = "ip"
	MonitorTypeSite   MonitorType = "site"
	MonitorTypeGithub MonitorType = "github"
	MonitorTypeWIH    MonitorType = "wih"
)

// MonitorStatus 监控状态
type MonitorStatus string

const (
	MonitorStatusActive   MonitorStatus = "active"
	MonitorStatusPaused   MonitorStatus = "paused"
	MonitorStatusStopped  MonitorStatus = "stopped"
)

// Monitor 监控任务
type Monitor struct {
	ID          string        `gorm:"primaryKey;type:uuid" json:"id"`
	Name        string        `gorm:"type:varchar(255);not null" json:"name"`
	Type        MonitorType   `gorm:"type:varchar(50);not null" json:"type"`
	Target      string        `gorm:"type:text;not null" json:"target"`
	Status      MonitorStatus `gorm:"type:varchar(50);default:'active'" json:"status"`
	Interval    int           `gorm:"not null" json:"interval"` // 监控间隔（秒）
	LastRunTime *time.Time    `json:"last_run_time,omitempty"`
	NextRunTime *time.Time    `json:"next_run_time,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

func (m *Monitor) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = uuid.New().String()
	}
	return nil
}

func (Monitor) TableName() string {
	return "monitors"
}

// MonitorResult 监控结果
type MonitorResult struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	MonitorID   string    `gorm:"type:uuid;index;not null" json:"monitor_id"`
	ChangeType  string    `gorm:"type:varchar(100)" json:"change_type"` // new, modified, deleted
	Description string    `gorm:"type:text" json:"description"`
	Data        string    `gorm:"type:text" json:"data"` // JSON格式的变化数据
	CreatedAt   time.Time `json:"created_at"`
}

func (mr *MonitorResult) BeforeCreate(tx *gorm.DB) error {
	if mr.ID == "" {
		mr.ID = uuid.New().String()
	}
	return nil
}

func (MonitorResult) TableName() string {
	return "monitor_results"
}

// AssetGroup 资产分组
type AssetGroup struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Name        string    `gorm:"type:varchar(255);not null;unique" json:"name"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (ag *AssetGroup) BeforeCreate(tx *gorm.DB) error {
	if ag.ID == "" {
		ag.ID = uuid.New().String()
	}
	return nil
}

func (AssetGroup) TableName() string {
	return "asset_groups"
}

// AssetGroupItem 资产分组项
type AssetGroupItem struct {
	ID           string    `gorm:"primaryKey;type:uuid" json:"id"`
	GroupID      string    `gorm:"type:uuid;index;not null" json:"group_id"`
	AssetType    string    `gorm:"type:varchar(50);not null" json:"asset_type"` // domain, ip, site
	AssetID      string    `gorm:"type:uuid;not null" json:"asset_id"`
	CreatedAt    time.Time `json:"created_at"`
}

func (agi *AssetGroupItem) BeforeCreate(tx *gorm.DB) error {
	if agi.ID == "" {
		agi.ID = uuid.New().String()
	}
	return nil
}

func (AssetGroupItem) TableName() string {
	return "asset_group_items"
}
