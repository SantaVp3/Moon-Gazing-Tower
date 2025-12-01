package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TaskType represents different types of scan tasks
type TaskType string

const (
	TaskTypeAssetDiscovery TaskType = "asset_discovery"
	TaskTypePortScan       TaskType = "port_scan"
	TaskTypeFingerprint    TaskType = "fingerprint"
	TaskTypeVulnScan       TaskType = "vuln_scan"
	TaskTypeSubdomain      TaskType = "subdomain"
	TaskTypeTakeover       TaskType = "takeover"    // 子域名接管检测
	TaskTypeDirScan        TaskType = "dir_scan"
	TaskTypeCrawler        TaskType = "crawler"
	TaskTypeBruteforce     TaskType = "bruteforce"
	TaskTypeMonitor        TaskType = "monitor"
	TaskTypeFull           TaskType = "full"
)

// TaskStatus represents task execution status
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusPaused    TaskStatus = "paused"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// Task represents a scan task
type Task struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Type        TaskType           `json:"type" bson:"type"`
	Status      TaskStatus         `json:"status" bson:"status"`
	
	// Target Configuration
	Targets     []string `json:"targets" bson:"targets"` // IPs, domains, URLs
	TargetType  string   `json:"target_type" bson:"target_type"` // ip, domain, url, cidr
	
	// Task Configuration
	Config      TaskConfig `json:"config" bson:"config"`
	
	// Schedule Configuration
	IsScheduled bool   `json:"is_scheduled" bson:"is_scheduled"`
	CronExpr    string `json:"cron_expr,omitempty" bson:"cron_expr,omitempty"`
	
	// Execution Info
	Progress    int       `json:"progress" bson:"progress"` // 0-100
	NodeID      string    `json:"node_id" bson:"node_id"` // assigned scanner node
	StartedAt   time.Time `json:"started_at,omitempty" bson:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty" bson:"completed_at,omitempty"`
	
	// Results Summary
	ResultStats TaskResultStats `json:"result_stats" bson:"result_stats"`
	
	// Retry Info
	RetryCount  int    `json:"retry_count" bson:"retry_count"`
	LastError   string `json:"last_error,omitempty" bson:"last_error,omitempty"`
	
	// Metadata
	CreatedBy   primitive.ObjectID `json:"created_by" bson:"created_by"`
	Tags        []string           `json:"tags" bson:"tags"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

// TaskConfig represents task configuration options
type TaskConfig struct {
	// Scan Types (pipeline)
	ScanTypes     []string `json:"scan_types,omitempty" bson:"scan_types,omitempty"` // port_scan, subdomain, fingerprint, vuln_scan, crawler, dir_scan
	
	// Port Scan Config
	PortScanMode  string `json:"port_scan_mode,omitempty" bson:"port_scan_mode,omitempty"` // quick, full, top1000, custom
	PortRange     string `json:"port_range,omitempty" bson:"port_range,omitempty"` // e.g., "1-1000", "top100"
	PortScanRate  int    `json:"port_scan_rate,omitempty" bson:"port_scan_rate,omitempty"`
	
	// Subdomain Config
	SubdomainDict string `json:"subdomain_dict,omitempty" bson:"subdomain_dict,omitempty"`
	UsePassive    bool   `json:"use_passive,omitempty" bson:"use_passive,omitempty"`
	
	// Third-party API Config (for subdomain enumeration)
	UseThirdParty bool     `json:"use_thirdparty,omitempty" bson:"use_thirdparty,omitempty"` // 是否使用第三方 API
	ThirdPartySources []string `json:"thirdparty_sources,omitempty" bson:"thirdparty_sources,omitempty"` // fofa, hunter, quake, crtsh, securitytrails
	FofaEmail     string   `json:"fofa_email,omitempty" bson:"fofa_email,omitempty"`
	FofaKey       string   `json:"fofa_key,omitempty" bson:"fofa_key,omitempty"`
	HunterKey     string   `json:"hunter_key,omitempty" bson:"hunter_key,omitempty"`
	QuakeKey      string   `json:"quake_key,omitempty" bson:"quake_key,omitempty"`
	
	// Fingerprint Config
	EnableFingerprint bool `json:"enable_fingerprint,omitempty" bson:"enable_fingerprint,omitempty"`
	
	// Vuln Scan Config
	POCIDs        []string `json:"poc_ids,omitempty" bson:"poc_ids,omitempty"`
	POCTags       []string `json:"poc_tags,omitempty" bson:"poc_tags,omitempty"`
	SeverityFilter []string `json:"severity_filter,omitempty" bson:"severity_filter,omitempty"`
	
	// Dir Scan Config
	DirDict       string `json:"dir_dict,omitempty" bson:"dir_dict,omitempty"`
	Extensions    string `json:"extensions,omitempty" bson:"extensions,omitempty"`
	
	// Bruteforce Config
	ServiceType   string `json:"service_type,omitempty" bson:"service_type,omitempty"`
	UserDict      string `json:"user_dict,omitempty" bson:"user_dict,omitempty"`
	PassDict      string `json:"pass_dict,omitempty" bson:"pass_dict,omitempty"`
	
	// Crawler Config
	MaxDepth      int  `json:"max_depth,omitempty" bson:"max_depth,omitempty"`
	MaxPages      int  `json:"max_pages,omitempty" bson:"max_pages,omitempty"`
	FollowRedirect bool `json:"follow_redirect,omitempty" bson:"follow_redirect,omitempty"`
	
	// General Config
	Threads       int  `json:"threads,omitempty" bson:"threads,omitempty"`
	Timeout       int  `json:"timeout,omitempty" bson:"timeout,omitempty"`
	Proxy         string `json:"proxy,omitempty" bson:"proxy,omitempty"`
	VerifySSL     bool `json:"verify_ssl,omitempty" bson:"verify_ssl,omitempty"`
	ExcludeList   []string `json:"exclude_list,omitempty" bson:"exclude_list,omitempty"`
}

// TaskResultStats represents task result statistics
type TaskResultStats struct {
	TotalTargets     int `json:"total_targets" bson:"total_targets"`
	ScannedTargets   int `json:"scanned_targets" bson:"scanned_targets"`
	DiscoveredAssets int `json:"discovered_assets" bson:"discovered_assets"`
	DiscoveredVulns  int `json:"discovered_vulns" bson:"discovered_vulns"`
	DiscoveredPorts  int `json:"discovered_ports" bson:"discovered_ports"`
	// 用于断点续扫 - 记录已完成扫描的目标索引
	LastScannedIndex int      `json:"last_scanned_index" bson:"last_scanned_index"`
	// 记录已完成的扫描阶段（用于 full 类型任务）
	CompletedStages  []string `json:"completed_stages,omitempty" bson:"completed_stages,omitempty"`
}

// TaskTemplate represents reusable task templates
type TaskTemplate struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	Type        TaskType           `json:"type" bson:"type"`
	Config      TaskConfig         `json:"config" bson:"config"`
	IsPublic    bool               `json:"is_public" bson:"is_public"`
	CreatedBy   primitive.ObjectID `json:"created_by" bson:"created_by"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

// TaskLog represents task execution logs
type TaskLog struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	TaskID    primitive.ObjectID `json:"task_id" bson:"task_id"`
	Level     string             `json:"level" bson:"level"` // info, warn, error
	Message   string             `json:"message" bson:"message"`
	Detail    string             `json:"detail,omitempty" bson:"detail,omitempty"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

// Collection names for tasks
const (
	CollectionTasks         = "tasks"
	CollectionTaskTemplates = "task_templates"
	CollectionTaskLogs      = "task_logs"
)
