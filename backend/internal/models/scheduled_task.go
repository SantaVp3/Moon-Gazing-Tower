package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ScheduledTask 计划任务模型
type ScheduledTask struct {
	ID          string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	CronType    string         `gorm:"type:varchar(50);not null" json:"cron_type"`        // once, daily, weekly, monthly, custom
	CronExpr    string         `gorm:"type:varchar(100)" json:"cron_expr"`                // cron表达式，用于custom类型
	PolicyID    string         `gorm:"type:varchar(36);index" json:"policy_id,omitempty"` // 关联的策略ID
	TaskOptions TaskOptions    `gorm:"embedded;embeddedPrefix:task_" json:"task_options"` // 任务配置
	IsEnabled   bool           `gorm:"default:true" json:"is_enabled"`
	LastRunAt   *time.Time     `json:"last_run_at,omitempty"`
	NextRunAt   *time.Time     `json:"next_run_at,omitempty"`
	RunCount    int            `gorm:"default:0" json:"run_count"`
	FailCount   int            `gorm:"default:0" json:"fail_count"`
	CreatedBy   string         `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (ScheduledTask) TableName() string {
	return "scheduled_tasks"
}

// BeforeCreate 创建前钩子
func (st *ScheduledTask) BeforeCreate(tx *gorm.DB) error {
	if st.ID == "" {
		st.ID = uuid.New().String()
	}
	return nil
}

// ScheduledTaskLog 计划任务执行日志
type ScheduledTaskLog struct {
	ID              string     `gorm:"type:varchar(36);primaryKey" json:"id"`
	ScheduledTaskID string     `gorm:"type:varchar(36);not null;index" json:"scheduled_task_id"`
	TaskID          string     `gorm:"type:varchar(36);index" json:"task_id"`   // 实际创建的任务ID
	Status          string     `gorm:"type:varchar(50);not null" json:"status"` // success, failed
	Message         string     `gorm:"type:text" json:"message"`
	StartTime       time.Time  `json:"start_time"`
	EndTime         *time.Time `json:"end_time,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// TableName 指定表名
func (ScheduledTaskLog) TableName() string {
	return "scheduled_task_logs"
}

// BeforeCreate 创建前钩子
func (l *ScheduledTaskLog) BeforeCreate(tx *gorm.DB) error {
	if l.ID == "" {
		l.ID = uuid.New().String()
	}
	return nil
}
