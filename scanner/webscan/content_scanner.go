package webscan

import (
	"crypto/tls"
	"moongazing/scanner/core"
	"net"
	"net/http"
	"time"
)

// ContentScanner handles content scanning (directory brute, sensitive info, crawler)
// 该扫描器的具体功能已拆分到以下文件：
//   - dir_scanner.go: 目录扫描 (DirBrute, QuickDirScan)
//   - sensitive_scanner.go: 敏感信息扫描 (ScanSensitiveInfo, BatchScanSensitive)
//   - crawler.go: Web 爬虫 (WebCrawler)
type ContentScanner struct {
	Timeout        time.Duration
	HTTPClient     *http.Client
	Concurrency    int
	UserAgent      string
	Wordlist       []string
	Extensions     []string
	FollowRedirect bool            // 是否跟随重定向
	MaxRedirects   int             // 最大重定向次数
	Filter         *core.ResponseFilter // 响应去重过滤器
}

// NewContentScanner creates a new content scanner
func NewContentScanner(concurrency int) *ContentScanner {
	if concurrency <= 0 {
		concurrency = core.DefaultContentScanConcurrency
	}

	return &ContentScanner{
		Timeout: core.DefaultHTTPTimeout,
		HTTPClient: &http.Client{
			Timeout: core.DefaultHTTPTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   core.ShortHTTPTimeout,
					KeepAlive: core.ShortHTTPTimeout,
				}).DialContext,
				MaxIdleConns:        core.MaxIdleConns,
				MaxIdleConnsPerHost: core.MaxIdleConnsPerHost,
				IdleConnTimeout:     core.IdleConnTimeout,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 手动处理重定向
			},
		},
		Concurrency:    concurrency,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Wordlist:       getWordlistFromConfig(),
		Extensions:     getExtensionsFromConfig(),
		FollowRedirect: true, // 默认跟随重定向
		MaxRedirects:   5,    // 最大5次重定向
		Filter:         core.NewResponseFilter(core.DefaultFilterConfig()),
	}
}
