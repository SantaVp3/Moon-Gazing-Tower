package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Fingerprint 指纹模型
type Fingerprint struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_fingerprint_unique" json:"name"`
	Category    string         `gorm:"type:varchar(100);not null;index" json:"category"`
	RuleType    string         `gorm:"type:varchar(50);not null;uniqueIndex:idx_fingerprint_unique" json:"rule_type"` // body, header, title, favicon, url
	RuleContent string         `gorm:"type:text;not null;uniqueIndex:idx_fingerprint_unique" json:"rule_content"`
	Confidence  int            `gorm:"default:80" json:"confidence"` // 0-100
	Description string         `gorm:"type:text" json:"description"`
	IsEnabled   bool           `gorm:"default:true" json:"is_enabled"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (Fingerprint) TableName() string {
	return "fingerprints"
}

// BeforeCreate 创建前钩子
func (f *Fingerprint) BeforeCreate(tx *gorm.DB) error {
	if f.ID == "" {
		f.ID = uuid.New().String()
	}
	return nil
}

