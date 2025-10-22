package models

import (
	"time"
)

// AssetProfile 资产画像
type AssetProfile struct {
	// 基础信息
	AssetType string    `json:"asset_type"` // domain, ip, site, port
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name"` // 资产名称（域名/IP/URL）
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// 标签
	Tags []AssetTag `json:"tags,omitempty"`

	// 关联资产统计
	RelatedDomains int `json:"related_domains"` // 关联域名数
	RelatedIPs     int `json:"related_ips"`     // 关联IP数
	RelatedPorts   int `json:"related_ports"`   // 关联端口数
	RelatedSites   int `json:"related_sites"`   // 关联站点数

	// 漏洞统计
	VulnStats VulnerabilityStats `json:"vuln_stats"`

	// 风险评分 (0-100)
	RiskScore    int    `json:"risk_score"`
	RiskLevel    string `json:"risk_level"`    // low, medium, high, critical
	RiskReasons  []string `json:"risk_reasons"` // 风险原因列表

	// 资产特征
	Features AssetFeatures `json:"features,omitempty"`

	// 最近活动
	LastScanTime   *time.Time `json:"last_scan_time,omitempty"`
	LastUpdateTime *time.Time `json:"last_update_time,omitempty"`
}

// VulnerabilityStats 漏洞统计
type VulnerabilityStats struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// AssetFeatures 资产特征
type AssetFeatures struct {
	// 域名特征
	IsCDN              bool     `json:"is_cdn,omitempty"`
	SubdomainCount     int      `json:"subdomain_count,omitempty"`
	TakeoverVulnerable bool     `json:"takeover_vulnerable,omitempty"`
	
	// IP特征
	Location  string   `json:"location,omitempty"`
	OS        string   `json:"os,omitempty"`
	OpenPorts []int    `json:"open_ports,omitempty"`
	
	// 站点特征
	Title        string   `json:"title,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Fingerprints []string `json:"fingerprints,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	HasScreenshot bool    `json:"has_screenshot,omitempty"`
	
	// 端口特征
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// AssetRelation 资产关系
type AssetRelation struct {
	SourceType string      `json:"source_type"` // domain, ip, site, port
	SourceID   string      `json:"source_id"`
	SourceName string      `json:"source_name"`
	TargetType string      `json:"target_type"`
	TargetID   string      `json:"target_id"`
	TargetName string      `json:"target_name"`
	Relation   string      `json:"relation"` // resolves_to, hosted_on, runs_on, related_to
	CreatedAt  time.Time   `json:"created_at"`
}

// AssetGraphNode 资产图谱节点
type AssetGraphNode struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Name     string            `json:"name"`
	Label    string            `json:"label"`
	Data     map[string]interface{} `json:"data,omitempty"`
	RiskLevel string           `json:"risk_level,omitempty"`
	Tags     []string          `json:"tags,omitempty"`
}

// AssetGraphEdge 资产图谱边
type AssetGraphEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
	Label    string `json:"label"`
}

// AssetGraph 资产关系图谱
type AssetGraph struct {
	Nodes []AssetGraphNode `json:"nodes"`
	Edges []AssetGraphEdge `json:"edges"`
}

// CSegmentAnalysis C段分析结果
type CSegmentAnalysis struct {
	CSegment     string   `json:"c_segment"`     // 例如: 192.168.1.0/24
	TotalIPs     int      `json:"total_ips"`     // 该C段总IP数
	ActiveIPs    []string `json:"active_ips"`    // 活跃IP列表
	TotalPorts   int      `json:"total_ports"`   // 总端口数
	TotalSites   int      `json:"total_sites"`   // 总站点数
	CommonPorts  []int    `json:"common_ports"`  // 常见开放端口
	RiskLevel    string   `json:"risk_level"`    // 风险等级
}

// AssetTimeline 资产时间线
type AssetTimeline struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // created, updated, scanned, vuln_found, tag_added
	Description string    `json:"description"`
	Details     string    `json:"details,omitempty"`
}
