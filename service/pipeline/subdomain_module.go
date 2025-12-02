package pipeline

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"moongazing/scanner/core"
	"moongazing/scanner/subdomain"
)

// SubdomainScanModule 子域名扫描模块
// 接收主域名，执行被动枚举，输出子域名结果
type SubdomainScanModule struct {
	BaseModule
	subfinder    *subdomain.SubfinderScanner
	resultChan   chan interface{}
	maxEnumTime  int // 最大枚举时间（分钟）
	resolveIP    bool
	dnsResolvers []string
}

// NewSubdomainScanModule 创建子域名扫描模块
func NewSubdomainScanModule(ctx context.Context, nextModule ModuleRunner, maxEnumTime int, resolveIP bool) *SubdomainScanModule {
	if maxEnumTime <= 0 {
		maxEnumTime = 10 // 默认最大10分钟
	}

	m := &SubdomainScanModule{
		BaseModule: BaseModule{
			name:       "SubdomainScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		subfinder:   subdomain.NewSubfinderScanner(),
		resultChan:  make(chan interface{}, 1000),
		maxEnumTime: maxEnumTime,
		resolveIP:   resolveIP,
		dnsResolvers: []string{
			"8.8.8.8:53",
			"1.1.1.1:53",
			"114.114.114.114:53",
		},
	}

	// 配置 subfinder
	m.subfinder.MaxEnumerationTime = maxEnumTime
	m.subfinder.Threads = 10
	m.subfinder.Timeout = 30

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
	// 注意：去重检查已在 scanSubdomains 的回调中完成，这里不再重复检查
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

// scanSubdomains 执行子域名扫描
func (m *SubdomainScanModule) scanSubdomains(domain string) {
	log.Printf("[%s] Starting subdomain scan for %s", m.name, domain)

	ctx, cancel := context.WithTimeout(m.ctx, time.Duration(m.maxEnumTime+2)*time.Minute)
	defer cancel()

	// 使用回调函数实时处理结果
	err := m.subfinder.ScanWithCallback(ctx, domain, func(subdomain string) {
		// 去重检查
		if m.dupChecker.IsSubdomainDuplicate(subdomain) {
			return
		}

		result := SubdomainResult{
			Domain: subdomain,
			Source: "subfinder",
		}

		// 可选：解析 IP
		if m.resolveIP {
			ips := m.resolveIPs(subdomain)
			result.IPs = ips
		}

		log.Printf("[%s] Found subdomain: %s", m.name, subdomain)

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- result:
		}
	})

	if err != nil {
		log.Printf("[%s] Subfinder error for %s: %v", m.name, domain, err)
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

// SubdomainSecurityModule 子域名安全检测模块
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
		domainScanner:   subdomain.NewDomainScanner(10), // 默认10并发
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
	// if m.checkTakeover {
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
	// }

	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- result:
	}
}
