package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AssetTag 资产标签
type AssetTag struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	Name        string    `gorm:"type:varchar(100);not null;uniqueIndex" json:"name"`
	Color       string    `gorm:"type:varchar(20);default:'#3B82F6'" json:"color"` // 标签颜色
	Description string    `gorm:"type:text" json:"description,omitempty"`
	Category    string    `gorm:"type:varchar(50)" json:"category,omitempty"` // 标签分类：业务线、重要性、环境等
	CreatedBy   string    `gorm:"type:uuid" json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (at *AssetTag) BeforeCreate(tx *gorm.DB) error {
	if at.ID == "" {
		at.ID = uuid.New().String()
	}
	return nil
}

func (AssetTag) TableName() string {
	return "asset_tags"
}

// AssetTagRelation 资产与标签关联
type AssetTagRelation struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	TagID     string    `gorm:"type:uuid;not null;index:idx_tag" json:"tag_id"`
	AssetType string    `gorm:"type:varchar(50);not null;index:idx_asset" json:"asset_type"` // domain, ip, site, port
	AssetID   string    `gorm:"type:uuid;not null;index:idx_asset" json:"asset_id"`
	CreatedBy string    `gorm:"type:uuid" json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (atr *AssetTagRelation) BeforeCreate(tx *gorm.DB) error {
	if atr.ID == "" {
		atr.ID = uuid.New().String()
	}
	return nil
}

func (AssetTagRelation) TableName() string {
	return "asset_tag_relations"
}

// CreateTagRequest 创建标签请求
type CreateTagRequest struct {
	Name        string `json:"name" binding:"required"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// UpdateTagRequest 更新标签请求
type UpdateTagRequest struct {
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

// AddAssetTagRequest 为资产添加标签请求
type AddAssetTagRequest struct {
	TagIDs    []string `json:"tag_ids" binding:"required"`
	AssetType string   `json:"asset_type" binding:"required"` // domain, ip, site, port
	AssetID   string   `json:"asset_id" binding:"required"`
}
