package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SensitiveRuleType 规则类型
type SensitiveRuleType string

const (
	SensitiveRuleTypeRegex   SensitiveRuleType = "regex"   // 正则表达式
	SensitiveRuleTypeKeyword SensitiveRuleType = "keyword" // 关键词匹配
)

// SensitiveRuleSeverity 严重等级
type SensitiveRuleSeverity string

const (
	SensitiveRuleSeverityHigh   SensitiveRuleSeverity = "high"   // 高危
	SensitiveRuleSeverityMedium SensitiveRuleSeverity = "medium" // 中危
	SensitiveRuleSeverityLow    SensitiveRuleSeverity = "low"    // 低危
)

// SensitiveRule 敏感信息规则模型
type SensitiveRule struct {
	ID          string                `gorm:"type:varchar(36);primaryKey" json:"id"`
	Name        string                `gorm:"type:varchar(255);not null;index" json:"name"`               // 规则名称
	Type        SensitiveRuleType     `gorm:"type:varchar(50);not null;default:'regex'" json:"type"`      // 规则类型
	Pattern     string                `gorm:"type:text;not null" json:"pattern"`                          // 匹配模式（正则或关键词）
	Description string                `gorm:"type:text" json:"description"`                               // 规则描述
	Severity    SensitiveRuleSeverity `gorm:"type:varchar(50);not null;default:'medium'" json:"severity"` // 严重等级
	IsEnabled   bool                  `gorm:"default:true;index" json:"is_enabled"`                       // 是否启用
	IsBuiltIn   bool                  `gorm:"default:false" json:"is_built_in"`                           // 是否内置规则（内置规则不可删除）
	MatchCount  int                   `gorm:"default:0" json:"match_count"`                               // 匹配次数统计
	Category    string                `gorm:"type:varchar(100);index" json:"category"`                    // 分类（如：API密钥、证书、数据库等）
	Example     string                `gorm:"type:text" json:"example"`                                   // 示例（用于说明）
	CreatedBy   string                `gorm:"type:varchar(36)" json:"created_by"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
	DeletedAt   gorm.DeletedAt        `gorm:"index" json:"deleted_at,omitempty"`
}

// TableName 指定表名
func (SensitiveRule) TableName() string {
	return "sensitive_rules"
}

// BeforeCreate GORM hook - 创建前自动生成ID
func (sr *SensitiveRule) BeforeCreate(tx *gorm.DB) error {
	if sr.ID == "" {
		sr.ID = uuid.New().String()
	}
	return nil
}

// SensitiveMatch 敏感信息匹配记录
type SensitiveMatch struct {
	ID          string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	TaskID      string    `gorm:"type:varchar(36);index" json:"task_id"` // 任务ID
	RuleID      string    `gorm:"type:varchar(36);index" json:"rule_id"` // 规则ID
	RuleName    string    `gorm:"type:varchar(255)" json:"rule_name"`    // 规则名称（快照）
	URL         string    `gorm:"type:text" json:"url"`                  // 发现URL
	MatchedText string    `gorm:"type:text" json:"matched_text"`         // 匹配的文本（脱敏）
	Context     string    `gorm:"type:text" json:"context"`              // 上下文
	Location    string    `gorm:"type:varchar(100)" json:"location"`     // 位置（body/header/js/comment）
	Severity    string    `gorm:"type:varchar(50)" json:"severity"`      // 严重等级（快照）
	CreatedAt   time.Time `json:"created_at"`
}

// TableName 指定表名
func (SensitiveMatch) TableName() string {
	return "sensitive_matches"
}

// BeforeCreate GORM hook
func (sm *SensitiveMatch) BeforeCreate(tx *gorm.DB) error {
	if sm.ID == "" {
		sm.ID = uuid.New().String()
	}
	return nil
}
