package core

import "time"

// 扫描器默认配置常量
const (
	// 并发数配置
	DefaultFingerprintConcurrency = 20  // 指纹识别默认并发数
	DefaultVulnScanConcurrency    = 10  // 漏洞扫描默认并发数
	DefaultDNSConcurrency         = 200 // DNS查询默认并发数
	DefaultPortScanConcurrency    = 50  // 端口扫描默认并发数
	DefaultCrawlerConcurrency     = 10  // 爬虫默认并发数
	DefaultContentScanConcurrency = 20  // 内容扫描默认并发数

	// HTTP 客户端超时配置
	DefaultHTTPTimeout      = 10 * time.Second  // 默认 HTTP 请求超时
	LongHTTPTimeout         = 30 * time.Second  // 长时间 HTTP 请求超时
	ShortHTTPTimeout        = 5 * time.Second   // 短时间 HTTP 请求超时
	FingerprintHTTPTimeout  = 15 * time.Second  // 指纹识别 HTTP 超时
	VulnScanHTTPTimeout     = 30 * time.Second  // 漏洞扫描 HTTP 超时
	ContentScanHTTPTimeout  = 20 * time.Second  // 内容扫描 HTTP 超时

	// 扫描任务超时配置
	QuickScanTimeout     = 60 * time.Second   // 快速扫描超时
	DefaultScanTimeout   = 5 * time.Minute    // 默认扫描超时
	FullScanTimeout      = 30 * time.Minute   // 完整扫描超时
	SubdomainScanTimeout = 10 * time.Minute   // 子域名扫描超时
	PortScanTimeout      = 15 * time.Minute   // 端口扫描超时
	VulnScanTimeout      = 20 * time.Minute   // 漏洞扫描超时

	// 缓冲区大小
	DefaultResultChanBuffer = 1000 // 结果通道缓冲区大小
	DefaultInputChanBuffer  = 500  // 输入通道缓冲区大小
	DefaultWorkerChanBuffer = 100  // 工作通道缓冲区大小

	// 重试配置
	DefaultMaxRetries   = 3                    // 默认最大重试次数
	DefaultRetryDelay   = time.Second          // 默认重试延迟
	MaxRetryDelay       = 30 * time.Second     // 最大重试延迟

	// DNS 配置
	DNSTimeout     = 5 * time.Second  // DNS 查询超时
	DNSRetryCount  = 2                // DNS 重试次数
)

// HTTP Transport 配置
const (
	MaxIdleConns        = 100              // 最大空闲连接数
	MaxIdleConnsPerHost = 10               // 每个主机最大空闲连接数
	IdleConnTimeout     = 90 * time.Second // 空闲连接超时
)
