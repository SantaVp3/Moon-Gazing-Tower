package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GitHubMonitor GitHub监控模型
type GitHubMonitor struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	Keywords    string         `gorm:"type:text;not null" json:"keywords"` // 关键词，逗号分隔
	SearchType  string         `gorm:"type:varchar(50);not null" json:"search_type"` // code, repository, issue
	Language    string         `gorm:"type:varchar(50)" json:"language"`
	User        string         `gorm:"type:varchar(100)" json:"user"` // 限定用户/组织
	Repository  string         `gorm:"type:varchar(200)" json:"repository"` // 限定仓库
	Extension   string         `gorm:"type:varchar(50)" json:"extension"` // 文件扩展名
	IsEnabled   bool           `gorm:"default:true" json:"is_enabled"`
	Interval    int            `gorm:"not null;default:3600" json:"interval"` // 检查间隔（秒）
	LastRunAt   *time.Time     `json:"last_run_at,omitempty"`
	NextRunAt   *time.Time     `json:"next_run_at,omitempty"`
	RunCount    int            `gorm:"default:0" json:"run_count"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (GitHubMonitor) TableName() string {
	return "github_monitors"
}

// BeforeCreate 创建前钩子
func (m *GitHubMonitor) BeforeCreate(tx *gorm.DB) error {
	if m.ID == "" {
		m.ID = uuid.New().String()
	}
	return nil
}

// GitHubMonitorResult GitHub监控结果
type GitHubMonitorResult struct {
	ID          string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	MonitorID   string    `gorm:"type:varchar(36);not null;index" json:"monitor_id"`
	Title       string    `gorm:"type:varchar(500);not null" json:"title"`
	URL         string    `gorm:"type:varchar(1000);not null" json:"url"`
	Repository  string    `gorm:"type:varchar(200)" json:"repository"`
	Owner       string    `gorm:"type:varchar(100)" json:"owner"`
	FilePath    string    `gorm:"type:varchar(500)" json:"file_path"`
	Language    string    `gorm:"type:varchar(50)" json:"language"`
	Stars       int       `json:"stars"`
	Description string    `gorm:"type:text" json:"description"`
	MatchedText string    `gorm:"type:text" json:"matched_text"`
	IsRead      bool      `gorm:"default:false" json:"is_read"`
	CreatedAt   time.Time `json:"created_at"`
}

// TableName 指定表名
func (GitHubMonitorResult) TableName() string {
	return "github_monitor_results"
}

// BeforeCreate 创建前钩子
func (r *GitHubMonitorResult) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	return nil
}

