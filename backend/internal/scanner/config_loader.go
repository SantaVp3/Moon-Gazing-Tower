package scanner

import (
	"strconv"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// ScannerConfig 扫描器配置
type ScannerConfig struct {
	// 域名扫描配置
	DomainConcurrency             int
	DomainTimeout                 time.Duration
	DomainRetry                   int
	SubdomainTakeoverConcurrency  int

	// 端口扫描配置
	PortConcurrencySmall  int
	PortConcurrencyMedium int
	PortConcurrencyLarge  int
	PortTimeout           time.Duration

	// 站点扫描配置
	SiteConcurrency  int
	SiteTimeout      time.Duration
	CrawlerMaxDepth  int
	CrawlerMaxPages  int

	// 服务识别配置
	ServiceTimeout   time.Duration
	BannerMaxLength  int

	// IP地理位置配置
	IPLocationRateLimit  int
	IPLocationBatchSize  int
}

// LoadScannerConfig 从数据库加载扫描器配置
func LoadScannerConfig(ctx *ScanContext) *ScannerConfig {
	config := &ScannerConfig{
		// 默认值 - 域名扫描
		DomainConcurrency:            50,
		DomainTimeout:                3 * time.Second,
		DomainRetry:                  2,
		SubdomainTakeoverConcurrency: 20,

		// 默认值 - 端口扫描
		PortConcurrencySmall:  100,
		PortConcurrencyMedium: 300,
		PortConcurrencyLarge:  500,
		PortTimeout:           1500 * time.Millisecond, // 1.5秒

		// 默认值 - 站点扫描
		SiteConcurrency: 30,
		SiteTimeout:     5 * time.Second,
		CrawlerMaxDepth: 3,
		CrawlerMaxPages: 500,

		// 默认值 - 服务识别
		ServiceTimeout:  3 * time.Second,
		BannerMaxLength: 2048,

		// 默认值 - IP地理位置
		IPLocationRateLimit: 10,
		IPLocationBatchSize: 20,
	}

	// 从数据库加载配置
	var settings []models.Setting
	ctx.DB.Where("category = ?", "scanner").Find(&settings)

	for _, setting := range settings {
		switch setting.Key {
		// 域名扫描配置
		case "domain_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.DomainConcurrency = val
			}
		case "domain_timeout":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.DomainTimeout = time.Duration(val) * time.Second
			}
		case "domain_retry":
			if val, err := strconv.Atoi(setting.Value); err == nil && val >= 0 {
				config.DomainRetry = val
			}
		case "subdomain_takeover_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.SubdomainTakeoverConcurrency = val
			}

		// 端口扫描配置
		case "port_concurrency_small":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.PortConcurrencySmall = val
			}
		case "port_concurrency_medium":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.PortConcurrencyMedium = val
			}
		case "port_concurrency_large":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.PortConcurrencyLarge = val
			}
		case "port_timeout":
			if val, err := strconv.ParseFloat(setting.Value, 64); err == nil && val > 0 {
				config.PortTimeout = time.Duration(val * float64(time.Second))
			}

		// 站点扫描配置
		case "site_concurrency":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.SiteConcurrency = val
			}
		case "site_timeout":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.SiteTimeout = time.Duration(val) * time.Second
			}
		case "crawler_max_depth":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.CrawlerMaxDepth = val
			}
		case "crawler_max_pages":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.CrawlerMaxPages = val
			}

		// 服务识别配置
		case "service_timeout":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.ServiceTimeout = time.Duration(val) * time.Second
			}
		case "banner_max_length":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.BannerMaxLength = val
			}

		// IP地理位置配置
		case "ip_location_rate_limit":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.IPLocationRateLimit = val
			}
		case "ip_location_batch_size":
			if val, err := strconv.Atoi(setting.Value); err == nil && val > 0 {
				config.IPLocationBatchSize = val
			}
		}
	}

	return config
}

