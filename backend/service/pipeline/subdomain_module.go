package pipeline

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"moongazing/scanner/core"
	"moongazing/scanner/subdomain"
	"moongazing/scanner/subdomain/thirdparty"
)

// SubdomainScanModule 子域名扫描模块
// 使用综合扫描器：主动枚举（字典爆破）为主，第三方API为辅
type SubdomainScanModule struct {
	BaseModule
	activeScanner *subdomain.ActiveScanner
	resultChan    chan interface{}
	config        *subdomain.ActiveScannerConfig
	apiConfig     *thirdparty.APIConfig
	resolveIP     bool
	dnsResolvers  []string
}

// SubdomainScanConfig 子域名扫描配置
type SubdomainScanConfig struct {
	// 主动枚举配置
	BruteConcurrency int  // 字典爆破并发数 (默认 500)
	EnableBrute      bool // 是否启用字典爆破 (默认 true)
	EnableRecursive  bool // 是否启用递归爆破 (默认 false)
	RecursiveDepth   int  // 递归深度 (默认 2)

	// API 配置
	EnableAPI     bool     // 是否启用第三方API (默认 true)
	APISources    []string // 启用的API源
	APIMaxResults int      // 每个API最大结果数 (默认 500)

	// API 密钥
	FofaEmail         string
	FofaKey           string
	HunterKey         string
	QuakeKey          string
	SecurityTrailsKey string

	// 其他
	ResolveIP        bool // 是否解析IP (默认 true)
	VerifySubdomains bool // 是否验证子域名存活 (默认 true)
}

// DefaultSubdomainScanConfig 默认配置
func DefaultSubdomainScanConfig() *SubdomainScanConfig {
	return &SubdomainScanConfig{
		BruteConcurrency: 500,
		EnableBrute:      true,
		EnableRecursive:  false,
		RecursiveDepth:   2,
		EnableAPI:        false, // 默认关闭API，只使用字典爆破
		APISources:       []string{},
		APIMaxResults:    500,
		ResolveIP:        true,
		VerifySubdomains: true,
	}
}

// NewSubdomainScanModule 创建子域名扫描模块（新版本，使用综合扫描器）
func NewSubdomainScanModule(ctx context.Context, nextModule ModuleRunner, maxEnumTime int, resolveIP bool) *SubdomainScanModule {
	// 兼容旧接口，使用默认配置
	cfg := DefaultSubdomainScanConfig()
	cfg.ResolveIP = resolveIP
	return NewSubdomainScanModuleWithConfig(ctx, nextModule, cfg)
}

// NewSubdomainScanModuleWithConfig 使用完整配置创建子域名扫描模块
func NewSubdomainScanModuleWithConfig(ctx context.Context, nextModule ModuleRunner, scanConfig *SubdomainScanConfig) *SubdomainScanModule {
	if scanConfig == nil {
		scanConfig = DefaultSubdomainScanConfig()
	}

	// 构建 ActiveScanner 配置
	activeCfg := &subdomain.ActiveScannerConfig{
		BruteConcurrency:  scanConfig.BruteConcurrency,
		EnableBrute:       scanConfig.EnableBrute,
		EnableRecursive:   scanConfig.EnableRecursive,
		RecursiveDepth:    scanConfig.RecursiveDepth,
		WildcardDetection: true,
		ResolveTimeout:    3,
		EnableAPI:         scanConfig.EnableAPI,
		APISources:        scanConfig.APISources,
		APIMaxResults:     scanConfig.APIMaxResults,
		VerifySubdomains:  scanConfig.VerifySubdomains,
		EnableHTTPProbe:   false,
	}

	// 构建 API 配置
	apiCfg := &thirdparty.APIConfig{
		FofaEmail:         scanConfig.FofaEmail,
		FofaKey:           scanConfig.FofaKey,
		HunterKey:         scanConfig.HunterKey,
		QuakeKey:          scanConfig.QuakeKey,
		SecurityTrailsKey: scanConfig.SecurityTrailsKey,
	}

	m := &SubdomainScanModule{
		BaseModule: BaseModule{
			name:       "SubdomainScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		activeScanner: subdomain.NewActiveScanner(activeCfg, apiCfg),
		resultChan:    make(chan interface{}, 2000), // 增大缓冲区
		config:        activeCfg,
		apiConfig:     apiCfg,
		resolveIP:     scanConfig.ResolveIP,
		dnsResolvers: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"114.114.114.114:53",
			"223.5.5.5:53",
		},
	}

	return m
}

// ModuleRun 运行模块
func (m *SubdomainScanModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 启动下一个模块
	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 结果处理协程 - 发送到下一个模块
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			// 发送到下一个模块
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- result:
					log.Printf("[%s] Sent result to next module: %+v", m.name, result)
				}
			}
		}
		// 关闭下一个模块的输入
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	for {
		select {
		case <-m.ctx.Done():
			allWg.Wait()
			close(m.resultChan)
			resultWg.Wait()
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				// 输入通道关闭
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}

			// 处理字符串类型的主域名
			domain, ok := data.(string)
			if !ok {
				// 尝试 SubdomainResult 类型
				if sr, ok := data.(SubdomainResult); ok {
					domain = sr.Domain
				} else {
					log.Printf("[%s] Unexpected data type: %T", m.name, data)
					continue
				}
			}

			allWg.Add(1)
			go func(d string) {
				defer allWg.Done()
				m.scanSubdomains(d)
			}(domain)
		}
	}
}

// scanSubdomains 执行子域名扫描（使用综合扫描器）
func (m *SubdomainScanModule) scanSubdomains(domain string) {
	log.Printf("[%s] Starting comprehensive subdomain scan for %s", m.name, domain)
	log.Printf("[%s] Brute enabled: %v, API enabled: %v, Sources: %v",
		m.name, m.config.EnableBrute, m.config.EnableAPI, m.config.APISources)

	// 使用回调函数实时处理结果
	err := m.activeScanner.ScanWithCallback(m.ctx, domain, func(subResult subdomain.SubdomainResult) {
		// 去重检查
		if m.dupChecker.IsSubdomainDuplicate(subResult.FullDomain) {
			return
		}

		result := SubdomainResult{
			Domain: subResult.FullDomain,
			Source: "active", // 综合扫描
			IPs:    subResult.IPs,
		}

		// 如果没有 IP 且需要解析
		if m.resolveIP && len(result.IPs) == 0 {
			result.IPs = m.resolveIPs(subResult.FullDomain)
		}

		log.Printf("[%s] Found subdomain: %s (IPs: %v)", m.name, subResult.FullDomain, result.IPs)

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- result:
		}
	})

	if err != nil {
		log.Printf("[%s] Scan error for %s: %v", m.name, domain, err)
	}

	log.Printf("[%s] Subdomain scan completed for %s", m.name, domain)
}

// resolveIPs 解析域名的 IP 地址
func (m *SubdomainScanModule) resolveIPs(domain string) []string {
	var ips []string

	// 使用自定义 resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			// 随机选择一个 DNS 服务器
			dnsServer := m.dnsResolvers[0]
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return ips
	}

	for _, addr := range addrs {
		ips = append(ips, addr.IP.String())
	}

	return ips
}

// DomainVerifyModule 子域名安全检测模块
// 执行子域名接管检测、DNS解析等
type DomainVerifyModule struct {
	BaseModule
	domainScanner   *subdomain.DomainScanner
	takeoverScanner *subdomain.TakeoverScanner
	resultChan      chan interface{}
	concurrency     int
}

// NewDomainVerifyModule 创建域名验证模块
func NewDomainVerifyModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *DomainVerifyModule {
	if concurrency <= 0 {
		concurrency = 50
	}

	m := &DomainVerifyModule{
		BaseModule: BaseModule{
			name:       "DomainVerify",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		domainScanner:   subdomain.NewDomainScanner(10),
		takeoverScanner: subdomain.NewTakeoverScanner(20),
		resultChan:      make(chan interface{}, 500),
		concurrency:     concurrency,
	}
	return m
}

// ModuleRun 运行模块
func (m *DomainVerifyModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 启动下一个模块
	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	// 结果处理协程
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			// 发送到下一个模块
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- result:
				}
			}
		}
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	// 处理输入
	for {
		select {
		case <-m.ctx.Done():
			allWg.Wait()
			close(m.resultChan)
			resultWg.Wait()
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if !ok {
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				log.Printf("[%s] Input closed, waiting for next module", m.name)
				nextModuleRun.Wait()
				return nil
			}

			// 处理 SubdomainResult
			subResult, ok := data.(SubdomainResult)
			if !ok {
				log.Printf("[%s] Unexpected data type: %T, value: %+v", m.name, data, data)
				continue
			}

			allWg.Add(1)
			go func(sr SubdomainResult) {
				defer allWg.Done()
				m.checkSubdomain(sr)
			}(subResult)
		}
	}
}

// checkSubdomain 检查子域名安全
func (m *DomainVerifyModule) checkSubdomain(sr SubdomainResult) {
	// 【重要】先传递原始的 SubdomainResult，确保它被收集到
	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- sr:
	}

	// 解析 DNS 获取更多信息
	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	// 使用 DomainScanner 检查子域名
	rootDomain := core.ExtractRootDomain(sr.Domain)
	checkResult := m.domainScanner.CheckSubdomain(ctx, sr.Domain, rootDomain)

	// 构建 DomainResolve 结果
	result := DomainResolve{
		Domain: sr.Domain,
		IP:     sr.IPs,
	}

	// 如果有更多的 IP 信息，使用检查结果
	if checkResult != nil {
		if len(checkResult.IPs) > 0 {
			result.IP = checkResult.IPs
		}

		// 记录存活状态和 HTTP 信息
		if checkResult.Alive {
			log.Printf("[%s] %s is alive (HTTP: %d, HTTPS: %d)",
				m.name, sr.Domain, checkResult.HTTPStatus, checkResult.HTTPSStatus)
		}
	}

	// 子域名接管检测
	takeoverResult, err := m.takeoverScanner.Scan(ctx, sr.Domain)
	if err != nil {
		log.Printf("[%s] Takeover scan error for %s: %v", m.name, sr.Domain, err)
	} else if takeoverResult != nil && takeoverResult.Vulnerable {
		log.Printf("[%s] Potential subdomain takeover detected: %s (Service: %s, CNAME: %s)",
			m.name, sr.Domain, takeoverResult.Service, takeoverResult.CNAME)
		// 发送接管检测结果
		takeoverRes := TakeoverResult{
			Domain:       takeoverResult.Domain,
			CNAME:        takeoverResult.CNAME,
			Service:      takeoverResult.Service,
			Vulnerable:   takeoverResult.Vulnerable,
			Fingerprints: takeoverResult.Fingerprints,
			Reason:       takeoverResult.Reason,
		}
		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- takeoverRes:
		}
	}

	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- result:
	}
}
