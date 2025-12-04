package subdomain

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"moongazing/config"
	"moongazing/scanner/subdomain/thirdparty"
)

// DNS 服务器列表
var dnsServers = []string{
	"8.8.8.8:53",         // Google
	"1.1.1.1:53",         // Cloudflare
	"223.5.5.5:53",       // 阿里DNS
	"114.114.114.114:53", // 114 DNS
	"8.8.4.4:53",         // Google Secondary
	"1.0.0.1:53",         // Cloudflare Secondary
}

// ActiveScannerConfig 主动扫描配置
type ActiveScannerConfig struct {
	BruteConcurrency  int      // 爆破并发数
	EnableBrute       bool     // 是否启用爆破
	EnableRecursive   bool     // 是否启用递归
	RecursiveDepth    int      // 递归深度
	WildcardDetection bool     // 泛解析检测
	ResolveTimeout    int      // 解析超时(秒)
	EnableAPI         bool     // 是否启用API
	APISources        []string // API源列表
	APIMaxResults     int      // API最大结果数
	VerifySubdomains  bool     // 是否验证存活
	EnableHTTPProbe   bool     // 是否进行HTTP探测
}

// ActiveScanner 综合子域名扫描器
type ActiveScanner struct {
	config     *ActiveScannerConfig
	apiManager *thirdparty.APIManager
	results    sync.Map              // 存储去重后的结果 map[string]*SubdomainResult
	callback   func(SubdomainResult) // 结果回调函数
}

// NewActiveScanner 创建新的扫描器
func NewActiveScanner(cfg *ActiveScannerConfig, apiCfg *thirdparty.APIConfig) *ActiveScanner {
	return &ActiveScanner{
		config:     cfg,
		apiManager: thirdparty.NewAPIManager(apiCfg),
	}
}

// Run 执行扫描
func (s *ActiveScanner) Run(ctx context.Context, domain string) ([]SubdomainResult, error) {
	log.Printf("[ActiveScanner] Starting scan for domain: %s", domain)

	// 重置结果存储，确保每次扫描都是干净的
	s.results = sync.Map{}

	var wg sync.WaitGroup

	// 2. API 枚举（可选）
	if s.config.EnableAPI {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runAPIEnum(ctx, domain)
		}()
	}

	// 3. 字典爆破（可选）
	if s.config.EnableBrute {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runBruteForce(ctx, domain)
		}()
	}

	wg.Wait()

	// 收集结果
	var results []SubdomainResult
	s.results.Range(func(key, value interface{}) bool {
		if result, ok := value.(*SubdomainResult); ok {
			results = append(results, *result)
		}
		return true
	})

	log.Printf("[ActiveScanner] Scan completed for %s, found %d subdomains", domain, len(results))
	return results, nil
}

// runAPIEnum 执行API枚举（仅支持付费API: fofa, hunter, quake, securitytrails）
// 注意：crtsh 已移除，因为数据不准确
func (s *ActiveScanner) runAPIEnum(ctx context.Context, domain string) {
	log.Printf("[ActiveScanner] Starting API enumeration for %s", domain)

	var wg sync.WaitGroup

	// 调用各个 API（已移除 crtsh）
	for _, source := range s.config.APISources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			switch src {
			case "fofa":
				if s.apiManager.Fofa != nil {
					assets, err := s.apiManager.Fofa.SearchSubdomains(ctx, domain, s.config.APIMaxResults)
					if err == nil {
						for _, asset := range assets {
							var ips []string
							if asset.IP != "" {
								ips = []string{asset.IP}
							}
							s.addResult(asset.Host, ips, "fofa")
						}
						log.Printf("[ActiveScanner] Fofa found %d assets", len(assets))
					} else {
						log.Printf("[ActiveScanner] Fofa error: %v", err)
					}
				}
			case "hunter":
				if s.apiManager.Hunter != nil {
					assets, err := s.apiManager.Hunter.SearchSubdomains(ctx, domain, s.config.APIMaxResults)
					if err == nil {
						for _, asset := range assets {
							var ips []string
							if asset.IP != "" {
								ips = []string{asset.IP}
							}
							// Hunter 使用 Domain 或 URL 字段
							host := asset.Domain
							if host == "" {
								host = asset.URL
							}
							if host != "" {
								s.addResult(host, ips, "hunter")
							}
						}
						log.Printf("[ActiveScanner] Hunter found %d assets", len(assets))
					} else {
						log.Printf("[ActiveScanner] Hunter error: %v", err)
					}
				}
			case "quake":
				if s.apiManager.Quake != nil {
					assets, err := s.apiManager.Quake.SearchSubdomains(ctx, domain, s.config.APIMaxResults)
					if err == nil {
						for _, asset := range assets {
							var ips []string
							if asset.IP != "" {
								ips = []string{asset.IP}
							}
							// Quake 使用 Domain 或 Hostname 字段
							host := asset.Domain
							if host == "" {
								host = asset.Hostname
							}
							if host != "" {
								s.addResult(host, ips, "quake")
							}
						}
						log.Printf("[ActiveScanner] Quake found %d assets", len(assets))
					} else {
						log.Printf("[ActiveScanner] Quake error: %v", err)
					}
				}
			case "securitytrails":
				if s.apiManager.SecurityTrails != nil {
					subdomains, err := s.apiManager.SecurityTrails.SearchSubdomains(ctx, domain)
					if err == nil {
						for _, sub := range subdomains {
							s.addResult(sub, nil, "securitytrails")
						}
						log.Printf("[ActiveScanner] SecurityTrails found %d subdomains", len(subdomains))
					} else {
						log.Printf("[ActiveScanner] SecurityTrails error: %v", err)
					}
				}
			}
		}(source)
	}

	wg.Wait()
}

// runBruteForce 执行字典爆破
func (s *ActiveScanner) runBruteForce(ctx context.Context, domain string) {
	log.Printf("[ActiveScanner] Starting brute force for %s using ksubdomain", domain)

	// 获取字典
	subdomains := config.GetSubdomains()
	if len(subdomains) == 0 {
		log.Printf("[ActiveScanner] No dictionary loaded, skipping brute force")
		return
	}

	log.Printf("[ActiveScanner] Loaded %d subdomains from dictionary for %s", len(subdomains), domain)

	// 泛解析检测
	wildcardIPs := make(map[string]bool)
	var wildcardEnabled bool
	if s.config.WildcardDetection {
		if ips := s.detectWildcard(domain); len(ips) > 0 {
			log.Printf("[ActiveScanner] Wildcard detected for %s, IPs: %v (will filter these)", domain, ips)
			for _, ip := range ips {
				wildcardIPs[ip] = true
			}
			wildcardEnabled = true
		} else {
			log.Printf("[ActiveScanner] No wildcard detected for %s", domain)
		}
	}

	// 使用 ksubdomain 进行枚举
	runner := NewKSubdomainRunner()
	results, err := runner.RunEnumeration(ctx, domain, subdomains)
	if err != nil {
		log.Printf("[ActiveScanner] ksubdomain error: %v", err)
		return
	}

	log.Printf("[ActiveScanner] ksubdomain found %d potential subdomains", len(results))

	var added int64
	for sub, ips := range results {
		// 过滤泛解析
		if wildcardEnabled && len(wildcardIPs) > 0 {
			allWildcard := true
			for _, ip := range ips {
				if !wildcardIPs[ip] {
					allWildcard = false
					break
				}
			}
			if allWildcard {
				continue // 跳过泛解析结果
			}
		}

		s.addResult(sub, ips, "ksubdomain")
		added++
	}

	log.Printf("[ActiveScanner] Brute force completed, added %d new subdomains", added)
}

// resolveDomain 解析域名（使用多个DNS服务器并带重试机制）
func (s *ActiveScanner) resolveDomain(domain string) ([]string, error) {
	timeout := s.config.ResolveTimeout
	if timeout <= 0 {
		timeout = 5
	}

	// 随机选择一个DNS服务器开始
	startIdx := rand.Intn(len(dnsServers))

	// 尝试所有DNS服务器
	for i := 0; i < len(dnsServers); i++ {
		serverIdx := (startIdx + i) % len(dnsServers)
		dnsServer := dnsServers[serverIdx]

		// 创建自定义resolver
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(timeout) * time.Second,
				}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		ips, err := resolver.LookupHost(ctx, domain)
		cancel()

		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}

	// 所有DNS服务器都失败了，返回NXDOMAIN
	return nil, fmt.Errorf("no DNS record found")
}

// detectWildcard 检测泛解析，返回泛解析的IP
func (s *ActiveScanner) detectWildcard(domain string) []string {
	// 生成多个随机子域名进行测试
	testDomains := []string{
		fmt.Sprintf("wildcard-test-%d.%s", time.Now().UnixNano(), domain),
		fmt.Sprintf("random-check-%d.%s", time.Now().UnixNano()+1, domain),
		fmt.Sprintf("notexist-%d.%s", time.Now().UnixNano()+2, domain),
	}

	ipCounts := make(map[string]int)

	for _, testDomain := range testDomains {
		if ips, err := s.resolveDomain(testDomain); err == nil {
			for _, ip := range ips {
				ipCounts[ip]++
			}
		}
	}

	// 如果多个随机域名解析到相同IP，则认为是泛解析
	var wildcardIPs []string
	for ip, count := range ipCounts {
		if count >= 2 {
			wildcardIPs = append(wildcardIPs, ip)
		}
	}

	return wildcardIPs
}

// addResult 添加结果
func (s *ActiveScanner) addResult(subdomain string, ips []string, source string) {
	// 提取域名部分
	result := &SubdomainResult{
		Subdomain:  subdomain,
		FullDomain: subdomain,
		IPs:        ips,
		Alive:      true,
	}

	// 去重存储
	if _, loaded := s.results.LoadOrStore(subdomain, result); !loaded {
		log.Printf("[ActiveScanner] Found: %s -> %v (%s)", subdomain, ips, source)

		// 调用回调函数（如果设置了）
		if s.callback != nil {
			s.callback(*result)
		}
	}
}

// ScanWithCallback 使用回调函数进行扫描
func (s *ActiveScanner) ScanWithCallback(ctx context.Context, domain string, callback func(SubdomainResult)) error {
	s.callback = callback
	_, err := s.Run(ctx, domain)
	return err
}
