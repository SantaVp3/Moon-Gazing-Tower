package models

import (
	"time"
)

// Dictionary 字典模型
type Dictionary struct {
	ID          uint      `json:"id" gorm:"primaryKey;autoIncrement"`
	Name        string    `json:"name" gorm:"size:255;not null;index"`
	Type        string    `json:"type" gorm:"size:50;not null;index"` // port, directory, brute_force
	Category    string    `json:"category" gorm:"size:100;index"`     // 分类：ssh, mysql, http, top100, common等
	Content     string    `json:"content" gorm:"type:text"`           // 字典内容（适合小字典，直接存储）
	FilePath    string    `json:"file_path" gorm:"size:500"`          // 文件路径（大字典，存储到文件）
	Size        int       `json:"size"`                               // 条目数量
	IsBuiltIn   bool      `json:"is_built_in" gorm:"default:false"`   // 是否内置字典
	IsEnabled   bool      `json:"is_enabled" gorm:"default:true"`     // 是否启用
	Description string    `json:"description" gorm:"type:text"`       // 描述
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TableName 指定表名
func (Dictionary) TableName() string {
	return "dictionaries"
}

// DictionaryType 字典类型
const (
	DictTypePort       = "port"        // 端口字典
	DictTypeDirectory  = "directory"   // 目录字典
	DictTypeBruteForce = "brute_force" // 爆破字典
)

// DictionaryCategory 字典分类
const (
	// 端口字典分类
	DictCategoryPortTop100  = "top100"
	DictCategoryPortTop1000 = "top1000"
	DictCategoryPortAll     = "all"
	DictCategoryPortCustom  = "custom"

	// 目录字典分类
	DictCategoryDirCommon   = "common"
	DictCategoryDirBackup   = "backup"
	DictCategoryDirWebShell = "webshell"
	DictCategoryDirAdmin    = "admin"
	DictCategoryDirAPI      = "api"

	// 爆破字典分类
	DictCategoryBruteSSH      = "ssh"
	DictCategoryBruteMySQL    = "mysql"
	DictCategoryBruteRedis    = "redis"
	DictCategoryBruteFTP      = "ftp"
	DictCategoryBruteUsername = "username"
	DictCategoryBrutePassword = "password"
)
