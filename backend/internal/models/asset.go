package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Domain 域名资产
type Domain struct {
	ID                  string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID              string    `gorm:"type:uuid;uniqueIndex:idx_task_domain" json:"task_id"`
	Domain              string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_task_domain" json:"domain"`
	Source              string    `gorm:"type:varchar(100)" json:"source"` // 来源：brute, plugin, crawler等
	IPAddress           string    `gorm:"type:varchar(50)" json:"ip_address"`
	CDN                 bool      `gorm:"default:false" json:"cdn"`
	// 子域名接管检测字段
	TakeoverVulnerable  bool      `gorm:"default:false" json:"takeover_vulnerable"`
	TakeoverService     string    `gorm:"type:varchar(100)" json:"takeover_service,omitempty"`
	TakeoverCNAME       string    `gorm:"type:varchar(255)" json:"takeover_cname,omitempty"`
	TakeoverSeverity    string    `gorm:"type:varchar(50)" json:"takeover_severity,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func (d *Domain) BeforeCreate(tx *gorm.DB) error {
	if d.ID == "" {
		d.ID = uuid.New().String()
	}
	return nil
}

func (Domain) TableName() string {
	return "domains"
}

// IP IP资产
type IP struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID    string    `gorm:"type:uuid;uniqueIndex:idx_task_ip" json:"task_id"`
	IPAddress string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_task_ip" json:"ip_address"`
	Domain    string    `gorm:"type:varchar(255)" json:"domain,omitempty"`
	Source    string    `gorm:"type:varchar(100)" json:"source,omitempty"` // dns, c_segment, etc
	OS        string    `gorm:"type:varchar(100)" json:"os,omitempty"`
	CDN       bool      `gorm:"default:false" json:"cdn"`
	Location  string    `gorm:"type:varchar(255)" json:"location,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (i *IP) BeforeCreate(tx *gorm.DB) error {
	if i.ID == "" {
		i.ID = uuid.New().String()
	}
	return nil
}

func (IP) TableName() string {
	return "ips"
}

// Port 端口资产
type Port struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID      string    `gorm:"type:uuid;uniqueIndex:idx_task_ip_port" json:"task_id"`
	IPAddress   string    `gorm:"type:varchar(50);not null;uniqueIndex:idx_task_ip_port" json:"ip_address"`
	Port        int       `gorm:"not null;uniqueIndex:idx_task_ip_port" json:"port"`
	Protocol    string    `gorm:"type:varchar(20)" json:"protocol"` // tcp, udp
	Service     string    `gorm:"type:varchar(100)" json:"service,omitempty"`
	Version     string    `gorm:"type:varchar(255)" json:"version,omitempty"`
	Banner      string    `gorm:"type:text" json:"banner,omitempty"`
	SSLCert     string    `gorm:"type:text" json:"ssl_cert,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (p *Port) BeforeCreate(tx *gorm.DB) error {
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	return nil
}

func (Port) TableName() string {
	return "ports"
}

// Site 站点资产
type Site struct {
	ID           string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID       string    `gorm:"type:uuid;uniqueIndex:idx_task_url" json:"task_id"`
	URL          string    `gorm:"type:varchar(500);not null;uniqueIndex:idx_task_url" json:"url"`
	Title        string    `gorm:"type:varchar(255)" json:"title,omitempty"`
	StatusCode   int       `gorm:"default:0" json:"status_code"`
	IP           string    `gorm:"type:varchar(50)" json:"ip,omitempty"` // 添加IP字段
	ContentType  string    `gorm:"type:varchar(100)" json:"content_type,omitempty"`
	Server       string    `gorm:"type:varchar(100)" json:"server,omitempty"`
	Fingerprint  string    `gorm:"type:text" json:"fingerprint,omitempty"` // 添加单个指纹字段
	Fingerprints []string  `gorm:"type:text;serializer:json" json:"fingerprints,omitempty"`
	Screenshot   string    `gorm:"type:varchar(500)" json:"screenshot,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (s *Site) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

func (Site) TableName() string {
	return "sites"
}

// URL URL资产
type URL struct {
	ID        string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID    string    `gorm:"type:uuid;index" json:"task_id"`
	SiteID    string    `gorm:"type:uuid;index" json:"site_id,omitempty"`
	URL       string    `gorm:"type:text;not null" json:"url"`
	Source    string    `gorm:"type:varchar(100)" json:"source"` // crawler, search_engine
	CreatedAt time.Time `json:"created_at"`
}

func (u *URL) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

func (URL) TableName() string {
	return "urls"
}

// Vulnerability 漏洞信息
type Vulnerability struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID      string    `gorm:"type:uuid;index" json:"task_id"`
	URL         string    `gorm:"type:text;not null" json:"url"`
	Type        string    `gorm:"type:varchar(100)" json:"type"` // file_leak, nuclei, host_collision, xray, custom
	VulnType    string    `gorm:"type:varchar(100)" json:"vuln_type"` // XSS, SQLi, SSRF, etc (别名，向后兼容)
	Severity    string    `gorm:"type:varchar(50)" json:"severity"` // critical, high, medium, low, info
	Title       string    `gorm:"type:varchar(255)" json:"title"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	Payload     string    `gorm:"type:text" json:"payload,omitempty"` // 攻击payload
	Proof       string    `gorm:"type:text" json:"proof,omitempty"` // 漏洞证明
	Solution    string    `gorm:"type:text" json:"solution,omitempty"`
	Reference   string    `gorm:"type:text" json:"reference,omitempty"`
	Source      string    `gorm:"type:varchar(50)" json:"source,omitempty"` // nuclei, xray, custom_script
	CreatedAt   time.Time `json:"created_at"`
}

func (v *Vulnerability) BeforeCreate(tx *gorm.DB) error {
	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	return nil
}

func (Vulnerability) TableName() string {
	return "vulnerabilities"
}

// CrawlerResult 爬虫结果
type CrawlerResult struct {
	ID          string    `gorm:"primaryKey;type:uuid" json:"id"`
	TaskID      string    `gorm:"type:uuid;index" json:"task_id"`
	URL         string    `gorm:"type:text;not null;index" json:"url"`
	Method      string    `gorm:"type:varchar(10)" json:"method"`
	StatusCode  int       `gorm:"default:0" json:"status_code"`
	ContentType string    `gorm:"type:varchar(100)" json:"content_type"`
	Source      string    `gorm:"type:varchar(50);index" json:"source"` // crawler, crawler_js, js_analysis
	HasParams   bool      `gorm:"default:false" json:"has_params"`
	HasForm     bool      `gorm:"default:false" json:"has_form"`
	CreatedAt   time.Time `json:"created_at"`
}

func (c *CrawlerResult) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}

func (CrawlerResult) TableName() string {
	return "crawler_results"
}
