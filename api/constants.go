package api

import "time"

// API 处理器超时常量
// 这些值可以被请求中的 timeout 参数覆盖
const (
	// 端口扫描超时
	QuickPortScanTimeout  = 60 * time.Second   // 快速端口扫描
	CustomPortScanTimeout = 120 * time.Second  // 自定义端口扫描
	FullPortScanTimeout   = 10 * time.Minute   // 完整端口扫描

	// 子域名扫描超时
	SubdomainScanTimeout     = 5 * time.Minute  // 子域名扫描
	SubdomainBruteScanTimeout = 10 * time.Minute // 子域名爆破

	// 指纹识别超时
	FingerprintScanTimeout = 3 * time.Minute // 指纹识别

	// 漏洞扫描超时
	VulnScanTimeout      = 10 * time.Minute // 漏洞扫描
	NucleiScanTimeout    = 10 * time.Minute // Nuclei 扫描
	TakeoverScanTimeout  = 10 * time.Minute // 子域名接管检测

	// 爬虫超时
	CrawlerTimeout = 5 * time.Minute // 爬虫扫描

	// 内容扫描超时
	ContentScanTimeout    = 10 * time.Minute // 敏感内容扫描
	DirScanTimeout        = 10 * time.Minute // 目录扫描

	// 快速操作超时
	QuickAPITimeout = 30 * time.Second // 快速 API 操作
)
