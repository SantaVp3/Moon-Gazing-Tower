package subdomain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// SubfinderScanner 被动子域名收集器
type SubfinderScanner struct {
	Threads            int    // 线程数
	Timeout            int    // 单个源的超时时间（秒）
	MaxEnumerationTime int    // 最大枚举时间（分钟）
	ProviderConfigPath string // API 配置文件路径（可选）
}

// SubfinderResult 子域名收集结果
type SubfinderResult struct {
	Domain     string   `json:"domain"`     // 收集到的子域名
	Host       string   `json:"host"`       // 主域名
	Source     string   `json:"source"`     // 数据来源
	IPs        []string `json:"ips"`        // 解析的 IP（可选）
	RecordType string   `json:"record_type"` // DNS 记录类型
}

// SubfinderScanResult 整体扫描结果
type SubfinderScanResult struct {
	Host       string            `json:"host"`        // 目标主域名
	Subdomains []SubfinderResult `json:"subdomains"`  // 收集到的子域名
	TotalFound int               `json:"total_found"` // 总数
	Duration   string            `json:"duration"`    // 扫描耗时
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
}

// NewSubfinderScanner 创建新的 subfinder 扫描器
func NewSubfinderScanner() *SubfinderScanner {
	return &SubfinderScanner{
		Threads:            10, // 默认 10 线程
		Timeout:            30, // 每个源 30 秒超时
		MaxEnumerationTime: 10, // 最大枚举 10 分钟
	}
}

// SetProviderConfig 设置 API 提供者配置文件路径
func (s *SubfinderScanner) SetProviderConfig(path string) {
	s.ProviderConfigPath = path
}

// Scan 执行被动子域名收集
func (s *SubfinderScanner) Scan(ctx context.Context, domain string) (*SubfinderScanResult, error) {
	result := &SubfinderScanResult{
		Host:       domain,
		Subdomains: make([]SubfinderResult, 0),
		StartTime:  time.Now(),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	subdomainChan := make(chan string, 1000)
	
	// 禁用 log 时间戳
	log.SetFlags(0)

	// 配置 subfinder 选项
	opts := &runner.Options{
		Threads:            s.Threads,
		Timeout:            s.Timeout,
		MaxEnumerationTime: s.MaxEnumerationTime,
		Domain:             []string{domain},
		Output:             &bytes.Buffer{}, // 不输出到文件
		ResultCallback: func(entry *resolve.HostEntry) {
			subdomainChan <- entry.Host
		},
	}

	// 如果有配置文件路径
	if s.ProviderConfigPath != "" {
		opts.ProviderConfig = s.ProviderConfigPath
	}

	// 创建 runner
	subfinderRunner, err := runner.NewRunner(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	// 启动结果收集 goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		for subdomain := range subdomainChan {
			mu.Lock()
			result.Subdomains = append(result.Subdomains, SubfinderResult{
				Domain: subdomain,
				Host:   domain,
				Source: "subfinder",
			})
			mu.Unlock()
			fmt.Printf("[subfinder] Found: %s\n", subdomain)
		}
	}()

	// 执行枚举
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(subdomainChan)
		if err := subfinderRunner.RunEnumerationWithCtx(ctx); err != nil {
			fmt.Printf("[subfinder] Enumeration error: %v\n", err)
		}
	}()

	// 等待枚举完成
	wg.Wait()
	<-done

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.TotalFound = len(result.Subdomains)

	return result, nil
}

// ScanWithCallback 执行被动子域名收集，使用回调函数处理结果
func (s *SubfinderScanner) ScanWithCallback(ctx context.Context, domain string, callback func(subdomain string)) error {
	log.SetFlags(0)

	opts := &runner.Options{
		Threads:            s.Threads,
		Timeout:            s.Timeout,
		MaxEnumerationTime: s.MaxEnumerationTime,
		Domain:             []string{domain},
		Output:             &bytes.Buffer{},
		ResultCallback: func(entry *resolve.HostEntry) {
			callback(entry.Host)
		},
	}

	if s.ProviderConfigPath != "" {
		opts.ProviderConfig = s.ProviderConfigPath
	}

	subfinderRunner, err := runner.NewRunner(opts)
	if err != nil {
		return fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	return subfinderRunner.RunEnumerationWithCtx(ctx)
}

// ScanMultipleDomains 批量扫描多个域名
func (s *SubfinderScanner) ScanMultipleDomains(ctx context.Context, domains []string) (map[string]*SubfinderScanResult, error) {
	results := make(map[string]*SubfinderScanResult)
	var mu sync.Mutex

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			result, err := s.Scan(ctx, domain)
			if err != nil {
				fmt.Printf("[subfinder] Error scanning %s: %v\n", domain, err)
				continue
			}
			mu.Lock()
			results[domain] = result
			mu.Unlock()
		}
	}

	return results, nil
}

// ScanToWriter 扫描并将结果写入 Writer
func (s *SubfinderScanner) ScanToWriter(ctx context.Context, domain string, w io.Writer) error {
	log.SetFlags(0)

	opts := &runner.Options{
		Threads:            s.Threads,
		Timeout:            s.Timeout,
		MaxEnumerationTime: s.MaxEnumerationTime,
		Domain:             []string{domain},
		Output:             w,
	}

	if s.ProviderConfigPath != "" {
		opts.ProviderConfig = s.ProviderConfigPath
	}

	subfinderRunner, err := runner.NewRunner(opts)
	if err != nil {
		return fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	return subfinderRunner.RunEnumerationWithCtx(ctx)
}

// GetUniqueSubdomains 从结果中获取去重的子域名列表
func (r *SubfinderScanResult) GetUniqueSubdomains() []string {
	seen := make(map[string]struct{})
	var unique []string

	for _, sub := range r.Subdomains {
		if _, exists := seen[sub.Domain]; !exists {
			seen[sub.Domain] = struct{}{}
			unique = append(unique, sub.Domain)
		}
	}

	return unique
}
