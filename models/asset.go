package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// AssetType represents different types of assets
type AssetType string

const (
	AssetTypeIP         AssetType = "ip"
	AssetTypeDomain     AssetType = "domain"
	AssetTypeSubdomain  AssetType = "subdomain"
	AssetTypeURL        AssetType = "url"
	AssetTypeAPP        AssetType = "app"
	AssetTypeMiniProgram AssetType = "miniprogram"
)

// Asset represents a discovered asset
type Asset struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Type        AssetType          `json:"type" bson:"type"`
	Value       string             `json:"value" bson:"value"` // IP, domain, URL etc.
	Title       string             `json:"title" bson:"title"`
	Status      int                `json:"status" bson:"status"` // 1: active, 0: inactive
	Tags        []string           `json:"tags" bson:"tags"`
	GroupID     primitive.ObjectID `json:"group_id" bson:"group_id"`
	
	// IP specific
	IPInfo *IPInfo `json:"ip_info,omitempty" bson:"ip_info,omitempty"`
	
	// Domain specific
	DomainInfo *DomainInfo `json:"domain_info,omitempty" bson:"domain_info,omitempty"`
	
	// Web specific
	WebInfo *WebInfo `json:"web_info,omitempty" bson:"web_info,omitempty"`
	
	// APP specific
	APPInfo *APPInfo `json:"app_info,omitempty" bson:"app_info,omitempty"`
	
	Source       string     `json:"source" bson:"source"` // manual, scan, import
	LastScanTime *time.Time `json:"last_scan_time,omitempty" bson:"last_scan_time,omitempty"`
	CreatedAt    time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at" bson:"updated_at"`
}

// IPInfo contains IP-specific information
type IPInfo struct {
	IP       string   `json:"ip" bson:"ip"`
	Ports    []Port   `json:"ports" bson:"ports"`
	OS       string   `json:"os" bson:"os"`
	ISP      string   `json:"isp" bson:"isp"`
	Country  string   `json:"country" bson:"country"`
	Region   string   `json:"region" bson:"region"`
	City     string   `json:"city" bson:"city"`
	IsCDN    bool     `json:"is_cdn" bson:"is_cdn"`
	CDNName  string   `json:"cdn_name" bson:"cdn_name"`
	IsCloud  bool     `json:"is_cloud" bson:"is_cloud"`
	CloudProvider string `json:"cloud_provider" bson:"cloud_provider"`
}

// Port represents a discovered port
type Port struct {
	Port     int    `json:"port" bson:"port"`
	Protocol string `json:"protocol" bson:"protocol"` // tcp, udp
	Service  string `json:"service" bson:"service"`
	Version  string `json:"version" bson:"version"`
	Banner   string `json:"banner" bson:"banner"`
	State    string `json:"state" bson:"state"` // open, closed, filtered
}

// DomainInfo contains domain-specific information
type DomainInfo struct {
	Domain     string   `json:"domain" bson:"domain"`
	IPs        []string `json:"ips" bson:"ips"`
	CNAME      []string `json:"cname" bson:"cname"`
	NS         []string `json:"ns" bson:"ns"`
	MX         []string `json:"mx" bson:"mx"`
	TXT        []string `json:"txt" bson:"txt"`
	Registrar  string   `json:"registrar" bson:"registrar"`
	ExpireDate string   `json:"expire_date" bson:"expire_date"`
	IsCDN      bool     `json:"is_cdn" bson:"is_cdn"`
}

// WebInfo contains web-specific information
type WebInfo struct {
	URL           string            `json:"url" bson:"url"`
	Title         string            `json:"title" bson:"title"`
	StatusCode    int               `json:"status_code" bson:"status_code"`
	ContentLength int               `json:"content_length" bson:"content_length"`
	Server        string            `json:"server" bson:"server"`
	Technologies  []string          `json:"technologies" bson:"technologies"`
	Fingerprints  []Fingerprint     `json:"fingerprints" bson:"fingerprints"`
	Headers       map[string]string `json:"headers" bson:"headers"`
	IconHash      string            `json:"icon_hash" bson:"icon_hash"`
	Screenshot    string            `json:"screenshot" bson:"screenshot"`
	SSL           *SSLInfo          `json:"ssl,omitempty" bson:"ssl,omitempty"`
}

// Fingerprint represents web fingerprint
type Fingerprint struct {
	Name     string `json:"name" bson:"name"`
	Version  string `json:"version" bson:"version"`
	Category string `json:"category" bson:"category"` // cms, framework, server, os
}

// SSLInfo contains SSL/TLS certificate information
type SSLInfo struct {
	Issuer     string    `json:"issuer" bson:"issuer"`
	Subject    string    `json:"subject" bson:"subject"`
	NotBefore  time.Time `json:"not_before" bson:"not_before"`
	NotAfter   time.Time `json:"not_after" bson:"not_after"`
	SANs       []string  `json:"sans" bson:"sans"`
	IsValid    bool      `json:"is_valid" bson:"is_valid"`
}

// APPInfo contains APP-specific information
type APPInfo struct {
	Name        string   `json:"name" bson:"name"`
	PackageName string   `json:"package_name" bson:"package_name"`
	Version     string   `json:"version" bson:"version"`
	Platform    string   `json:"platform" bson:"platform"` // android, ios
	DownloadURL string   `json:"download_url" bson:"download_url"`
	Permissions []string `json:"permissions" bson:"permissions"`
	APIs        []string `json:"apis" bson:"apis"`
}

// AssetGroup represents asset grouping
type AssetGroup struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Name        string             `json:"name" bson:"name"`
	Description string             `json:"description" bson:"description"`
	ParentID    primitive.ObjectID `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

// BlackWhiteList represents blacklist/whitelist for scanning
type BlackWhiteList struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	WorkspaceID primitive.ObjectID `json:"workspace_id" bson:"workspace_id"`
	Type        string             `json:"type" bson:"type"` // black, white
	Category    string             `json:"category" bson:"category"` // ip, domain, url
	Value       string             `json:"value" bson:"value"`
	Reason      string             `json:"reason" bson:"reason"`
	CreatedBy   primitive.ObjectID `json:"created_by" bson:"created_by"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
}

// AssetHistory represents asset change history
type AssetHistory struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	AssetID   primitive.ObjectID `json:"asset_id" bson:"asset_id"`
	Field     string             `json:"field" bson:"field"`
	OldValue  interface{}        `json:"old_value" bson:"old_value"`
	NewValue  interface{}        `json:"new_value" bson:"new_value"`
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}

// Collection names for assets
const (
	CollectionAssets         = "assets"
	CollectionAssetGroups    = "asset_groups"
	CollectionBlackWhiteList = "black_white_list"
	CollectionAssetHistory   = "asset_history"
)
