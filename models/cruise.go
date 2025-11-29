package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// CruiseStatus 巡航任务状态
type CruiseStatus string

const (
	CruiseStatusEnabled  CruiseStatus = "enabled"  // 启用
	CruiseStatusDisabled CruiseStatus = "disabled" // 禁用
	CruiseStatusRunning  CruiseStatus = "running"  // 执行中
)

// CruiseTask 巡航任务（定时自动扫描）
type CruiseTask struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Status      CruiseStatus       `json:"status" bson:"status"`

	// 定时配置
	CronExpr    string `json:"cron_expr" bson:"cron_expr"`       // Cron 表达式，如 "0 2 * * *" 每天凌晨2点
	Timezone    string `json:"timezone" bson:"timezone"`         // 时区，如 "Asia/Shanghai"
	
	// 扫描目标
	Targets     []string `json:"targets" bson:"targets"`         // 目标列表
	TargetType  string   `json:"target_type" bson:"target_type"` // ip, domain, url, cidr
	
	// 扫描配置（复用 TaskConfig）
	TaskType    TaskType   `json:"task_type" bson:"task_type"`     // 任务类型
	Config      TaskConfig `json:"config" bson:"config"`           // 扫描配置
	
	// 通知配置
	NotifyOnComplete bool     `json:"notify_on_complete" bson:"notify_on_complete"` // 完成后通知
	NotifyOnVuln     bool     `json:"notify_on_vuln" bson:"notify_on_vuln"`         // 发现漏洞时通知
	NotifyChannels   []string `json:"notify_channels" bson:"notify_channels"`       // 通知渠道

	// 执行统计
	LastRunAt     time.Time `json:"last_run_at,omitempty" bson:"last_run_at,omitempty"`
	NextRunAt     time.Time `json:"next_run_at,omitempty" bson:"next_run_at,omitempty"`
	RunCount      int       `json:"run_count" bson:"run_count"`             // 执行次数
	SuccessCount  int       `json:"success_count" bson:"success_count"`     // 成功次数
	FailCount     int       `json:"fail_count" bson:"fail_count"`           // 失败次数
	LastTaskID    string    `json:"last_task_id,omitempty" bson:"last_task_id,omitempty"` // 最近一次任务ID
	LastStatus    string    `json:"last_status,omitempty" bson:"last_status,omitempty"`   // 最近一次执行状态

	// 元数据
	CreatedBy primitive.ObjectID `json:"created_by" bson:"created_by"`
	Tags      []string           `json:"tags" bson:"tags"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time          `json:"updated_at" bson:"updated_at"`
}

// CruiseTaskCreateRequest 创建巡航任务请求
type CruiseTaskCreateRequest struct {
	Name             string     `json:"name" binding:"required"`
	Description      string     `json:"description"`
	CronExpr         string     `json:"cron_expr" binding:"required"` // Cron 表达式
	Timezone         string     `json:"timezone"`                     // 默认 Asia/Shanghai
	Targets          []string   `json:"targets" binding:"required"`
	TargetType       string     `json:"target_type"`
	TaskType         TaskType   `json:"task_type" binding:"required"`
	Config           TaskConfig `json:"config"`
	NotifyOnComplete bool       `json:"notify_on_complete"`
	NotifyOnVuln     bool       `json:"notify_on_vuln"`
	NotifyChannels   []string   `json:"notify_channels"`
	Tags             []string   `json:"tags"`
}

// CruiseTaskUpdateRequest 更新巡航任务请求
type CruiseTaskUpdateRequest struct {
	Name             *string     `json:"name"`
	Description      *string     `json:"description"`
	CronExpr         *string     `json:"cron_expr"`
	Timezone         *string     `json:"timezone"`
	Targets          []string    `json:"targets"`
	TargetType       *string     `json:"target_type"`
	TaskType         *TaskType   `json:"task_type"`
	Config           *TaskConfig `json:"config"`
	NotifyOnComplete *bool       `json:"notify_on_complete"`
	NotifyOnVuln     *bool       `json:"notify_on_vuln"`
	NotifyChannels   []string    `json:"notify_channels"`
	Tags             []string    `json:"tags"`
}

// CruiseLog 巡航执行日志
type CruiseLog struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	CruiseID    primitive.ObjectID `json:"cruise_id" bson:"cruise_id"`
	TaskID      primitive.ObjectID `json:"task_id" bson:"task_id"`
	Status      string             `json:"status" bson:"status"` // success, failed, running
	StartTime   time.Time          `json:"start_time" bson:"start_time"`
	EndTime     time.Time          `json:"end_time,omitempty" bson:"end_time,omitempty"`
	Duration    int64              `json:"duration" bson:"duration"` // 秒
	ResultCount int                `json:"result_count" bson:"result_count"`
	VulnCount   int                `json:"vuln_count" bson:"vuln_count"`
	Error       string             `json:"error,omitempty" bson:"error,omitempty"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
}

// GetCronDescription 获取 Cron 表达式的中文描述
func GetCronDescription(cronExpr string) string {
	// 常用 Cron 表达式映射
	descriptions := map[string]string{
		"0 * * * *":     "每小时执行",
		"0 */2 * * *":   "每2小时执行",
		"0 */6 * * *":   "每6小时执行",
		"0 */12 * * *":  "每12小时执行",
		"0 0 * * *":     "每天凌晨执行",
		"0 2 * * *":     "每天凌晨2点执行",
		"0 0 * * 0":     "每周日凌晨执行",
		"0 0 * * 1":     "每周一凌晨执行",
		"0 0 1 * *":     "每月1日凌晨执行",
		"0 0 1,15 * *":  "每月1日和15日凌晨执行",
	}
	
	if desc, ok := descriptions[cronExpr]; ok {
		return desc
	}
	return cronExpr
}
