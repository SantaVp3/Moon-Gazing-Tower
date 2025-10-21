package scanner

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"github.com/spf13/viper"
)

// DomainScanner 域名扫描器
type DomainScanner struct {
	dictionaries map[string][]string
	dnsResolvers []string
	timeout      time.Duration
	retryCount   int
}

// DomainStats 域名扫描统计
type DomainStats struct {
	TotalAttempts   int64
	ResolvedDomains int64
	FailedAttempts  int64
	StartTime       time.Time
}

// NewDomainScanner 创建域名扫描器
func NewDomainScanner() *DomainScanner {
	ds := &DomainScanner{
		dictionaries: make(map[string][]string),
		dnsResolvers: []string{
			"8.8.8.8:53",         // Google DNS
			"8.8.4.4:53",         // Google DNS Secondary
			"1.1.1.1:53",         // Cloudflare DNS
			"1.0.0.1:53",         // Cloudflare DNS Secondary
			"223.5.5.5:53",       // 阿里DNS
			"223.6.6.6:53",       // 阿里DNS Secondary
			"114.114.114.114:53", // 114DNS
			"114.114.115.115:53", // 114DNS Secondary
		},
		timeout:    5 * time.Second,
		retryCount: 2,
	}
	
	// 加载字典
	ds.loadDictionaries()
	
	return ds
}

// loadDictionaries 加载字典文件
func (ds *DomainScanner) loadDictionaries() {
	// 内置测试字典 - 扩展版
	ds.dictionaries["test"] = []string{
		"www", "mail", "ftp", "admin", "test", "dev", "api", "app",
		"m", "wap", "mobile", "blog", "forum", "bbs", "shop", "store",
		"vpn", "oa", "crm", "erp", "cdn", "img", "image", "static",
		"video", "live", "stream", "download", "upload", "cloud",
	}
	
	// 尝试从文件加载大字典
	bigDictPath := "./configs/dicts/domain/big.txt"
	if dict, err := ds.loadDictFromFile(bigDictPath); err == nil {
		ds.dictionaries["big"] = dict
	} else {
		// 如果文件不存在，使用生成的大字典
		ds.dictionaries["big"] = generateBigDict()
	}
}

// loadDictFromFile 从文件加载字典
func (ds *DomainScanner) loadDictFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dict []string
	scanner := bufio.NewScanner(file)
	// 增大缓冲区以处理长行
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 过滤空行和注释
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
			// 验证子域名格式
			if ds.isValidSubdomain(line) {
				dict = append(dict, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dict, nil
}

// loadDictFromDatabase 从数据库加载字典
func (ds *DomainScanner) loadDictFromDatabase(ctx *ScanContext, dictName string) ([]string, error) {
	// 查询数据库获取字典信息
	var dictionary models.Dictionary
	if err := ctx.DB.Where("name = ? AND type = ?", dictName, "domain").First(&dictionary).Error; err != nil {
		return nil, fmt.Errorf("dictionary not found: %s", dictName)
	}

	// 从文件路径加载字典内容
	return ds.loadDictFromFile(dictionary.FilePath)
}

// Scan 执行域名扫描
func (ds *DomainScanner) Scan(ctx *ScanContext) error {
	targets := strings.Split(ctx.Task.Target, ",")
	
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// 如果是域名，进行爆破
		if ds.isDomain(target) {
			// 保存主域名
			ds.saveDomain(ctx, target, "target", "")
			
			if ctx.Task.Options.EnableDomainBrute {
				if err := ds.bruteForceDomain(ctx, target); err != nil {
					ctx.Logger.Printf("Domain brute force failed: %v", err)
				}
			}

			// 使用插件查询域名
			if ctx.Task.Options.EnableDomainPlugins {
				if err := ds.queryDomainPlugins(ctx, target); err != nil {
					ctx.Logger.Printf("Domain plugins query failed: %v", err)
				}
			}
		}
	}

	// 扫描完成后，批量更新IP地理位置
	ctx.Logger.Printf("Updating IP locations in batch...")
	ds.updateIPLocationsInBatch(ctx)

	return nil
}

// bruteForceDomain 域名爆破（优化版）
func (ds *DomainScanner) bruteForceDomain(ctx *ScanContext, domain string) error {
	dictType := ctx.Task.Options.DomainBruteType
	if dictType == "" {
		dictType = "big" // 默认使用big字典
	}

	// 先尝试从内存字典加载
	dict, exists := ds.dictionaries[dictType]
	
	// 如果内存中不存在，尝试从数据库加载
	if !exists {
		ctx.Logger.Printf("Dictionary '%s' not in memory, trying to load from database...", dictType)
		loadedDict, err := ds.loadDictFromDatabase(ctx, dictType)
		if err != nil {
			ctx.Logger.Printf("Failed to load dictionary from database: %v, using test dict", err)
			dict = ds.dictionaries["test"]
		} else {
			dict = loadedDict
			ds.dictionaries[dictType] = loadedDict // 缓存到内存
			ctx.Logger.Printf("Loaded dictionary '%s' from database: %d entries", dictType, len(dict))
		}
	}

	if len(dict) == 0 {
		return fmt.Errorf("empty dictionary: %s", dictType)
	}

	ctx.Logger.Printf("=== Domain Brute Force Started ===")
	ctx.Logger.Printf("Target Domain: %s", domain)
	ctx.Logger.Printf("Dictionary: %s (%d entries)", dictType, len(dict))

	// 智能字典生成
	if ctx.Task.Options.SmartDictGen {
		smartDict := ds.generateSmartDict(ctx, domain)
		if len(smartDict) > 0 {
			ctx.Logger.Printf("Generated %d smart dictionary entries", len(smartDict))
			dict = append(dict, smartDict...)
		}
	}

	// 去重并验证
	uniqueDict := ds.deduplicateAndValidate(dict)
	ctx.Logger.Printf("Final dictionary size: %d entries (after deduplication)", len(uniqueDict))

	// 初始化统计
	stats := &DomainStats{
		TotalAttempts: int64(len(uniqueDict)),
		StartTime:     time.Now(),
	}

	// 根据字典大小动态调整并发数
	concurrency := ds.calculateConcurrency(len(uniqueDict))
	ctx.Logger.Printf("Concurrency: %d", concurrency)
	ctx.Logger.Printf("DNS Servers: %d", len(ds.dnsResolvers))
	ctx.Logger.Printf("Retry Count: %d", ds.retryCount)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)
	
	// 使用带缓冲的结果通道
	results := make(chan *DomainResult, 100)
	
	// 使用context支持取消
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动结果处理goroutine
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		ds.processResults(scanCtx, results, ctx, stats)
	}()

	// 进度报告goroutine
	go ds.reportProgress(scanCtx, stats, ctx)

	// 执行爆破
	for _, subdomain := range uniqueDict {
		select {
		case <-scanCtx.Done():
			break
		case <-ctx.Ctx.Done():
			ctx.Logger.Printf("Domain brute force cancelled by user")
			cancel()
			break
		default:
		}

		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fullDomain := sub + "." + domain
			
			// 解析域名（带重试）
			ips, err := ds.resolveWithRetry(fullDomain)
			if err == nil && len(ips) > 0 {
				// 发送结果
				select {
				case results <- &DomainResult{
					Domain: fullDomain,
					IPs:    ips,
					Source: "brute",
				}:
				case <-scanCtx.Done():
				}
			} else {
				atomic.AddInt64(&stats.FailedAttempts, 1)
			}
		}(subdomain)
	}

	// 等待所有扫描完成
	wg.Wait()
	close(results)
	
	// 等待结果处理完成
	resultWg.Wait()

	// 最终统计
	elapsed := time.Since(stats.StartTime)
	ctx.Logger.Printf("=== Domain Brute Force Completed ===")
	ctx.Logger.Printf("Resolved: %d", stats.ResolvedDomains)
	ctx.Logger.Printf("Failed: %d", stats.FailedAttempts)
	ctx.Logger.Printf("Total Attempts: %d", stats.TotalAttempts)
	ctx.Logger.Printf("Time Elapsed: %v", elapsed)
	ctx.Logger.Printf("Resolution Rate: %.2f domains/sec", float64(stats.TotalAttempts)/elapsed.Seconds())

	return nil
}

// DomainResult 域名解析结果
type DomainResult struct {
	Domain string
	IPs    []string
	Source string
}

// processResults 处理解析结果
func (ds *DomainScanner) processResults(ctx context.Context, results chan *DomainResult, scanCtx *ScanContext, stats *DomainStats) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok {
				return
			}
			
			// 验证域名有效性
			if ds.validateDomain(result.Domain, result.IPs) {
				atomic.AddInt64(&stats.ResolvedDomains, 1)
				scanCtx.Logger.Printf("[FOUND] %s -> %s", result.Domain, result.IPs[0])
				ds.saveDomain(scanCtx, result.Domain, result.Source, result.IPs[0])
				
				// 保存所有解析到的IP
				for _, ip := range result.IPs {
					ds.saveIP(scanCtx, ip, result.Domain)
				}
			}
		}
	}
}

// resolveWithRetry 带重试的DNS解析
func (ds *DomainScanner) resolveWithRetry(domain string) ([]string, error) {
	var lastErr error
	
	for i := 0; i <= ds.retryCount; i++ {
		// 使用不同的DNS服务器轮询
		dnsServer := ds.dnsResolvers[i%len(ds.dnsResolvers)]
		
		ips, err := ds.resolveWithDNS(domain, dnsServer)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		
		lastErr = err
		
		// 重试前短暂延迟
		if i < ds.retryCount {
			time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
		}
	}
	
	return nil, lastErr
}

// resolveWithDNS 使用指定DNS服务器解析
func (ds *DomainScanner) resolveWithDNS(domain string, dnsServer string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ds.timeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: ds.timeout,
			}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	
	// 过滤和去重IP
	return ds.filterIPs(ips), nil
}

// filterIPs 过滤和去重IP地址
func (ds *DomainScanner) filterIPs(ips []string) []string {
	seen := make(map[string]bool)
	var filtered []string
	
	for _, ip := range ips {
		// 跳过本地地址和无效地址
		if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "0.") {
			continue
		}
		
		// 跳过IPv6地址（可选）
		if strings.Contains(ip, ":") {
			continue
		}
		
		if !seen[ip] {
			seen[ip] = true
			filtered = append(filtered, ip)
		}
	}
	
	return filtered
}

// validateDomain 验证域名有效性
func (ds *DomainScanner) validateDomain(domain string, ips []string) bool {
	// 基本验证
	if len(ips) == 0 {
		return false
	}
	
	// 过滤泛解析（简单检测）
	// 如果解析到常见的泛解析IP，可能需要过滤
	wildcardIPs := map[string]bool{
		"127.0.0.1": true,
		"0.0.0.0":   true,
	}
	
	for _, ip := range ips {
		if wildcardIPs[ip] {
			return false
		}
	}
	
	return true
}

// deduplicateAndValidate 去重并验证字典
func (ds *DomainScanner) deduplicateAndValidate(dict []string) []string {
	seen := make(map[string]bool)
	var unique []string
	
	for _, entry := range dict {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" || seen[entry] {
			continue
		}
		
		// 验证子域名格式
		if ds.isValidSubdomain(entry) {
			seen[entry] = true
			unique = append(unique, entry)
		}
	}
	
	return unique
}

// isValidSubdomain 验证子域名格式
func (ds *DomainScanner) isValidSubdomain(subdomain string) bool {
	// 长度检查
	if len(subdomain) == 0 || len(subdomain) > 63 {
		return false
	}
	
	// 字符检查：只允许字母、数字、连字符，不能以连字符开头或结尾
	if strings.HasPrefix(subdomain, "-") || strings.HasSuffix(subdomain, "-") {
		return false
	}
	
	// 简单的正则验证
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	
	return true
}

// calculateConcurrency 计算合理的并发数
func (ds *DomainScanner) calculateConcurrency(dictSize int) int {
	// 小字典
	if dictSize < 100 {
		return 20
	}
	// 中等字典
	if dictSize < 1000 {
		return 50
	}
	// 大字典
	if dictSize < 10000 {
		return 100
	}
	// 超大字典
	return 200
}

// reportProgress 定期报告进度
func (ds *DomainScanner) reportProgress(ctx context.Context, stats *DomainStats, scanCtx *ScanContext) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resolved := atomic.LoadInt64(&stats.ResolvedDomains)
			failed := atomic.LoadInt64(&stats.FailedAttempts)
			total := stats.TotalAttempts
			attempted := resolved + failed
			
			if total > 0 {
				progress := float64(attempted) / float64(total) * 100
				elapsed := time.Since(stats.StartTime)
				rate := float64(attempted) / elapsed.Seconds()
				
				// 估算剩余时间
				remaining := time.Duration(0)
				if rate > 0 {
					remaining = time.Duration(float64(total-attempted)/rate) * time.Second
				}
				
				scanCtx.Logger.Printf("[Progress] %.1f%% (%d/%d) | Resolved: %d | Failed: %d | Rate: %.0f/s | ETA: %v",
					progress, attempted, total, resolved, failed, rate, remaining.Round(time.Second))
			}
		}
	}
}

// generateSmartDict 智能生成字典
func (ds *DomainScanner) generateSmartDict(ctx *ScanContext, domain string) []string {
	var dict []string
	
	// 从已发现的子域名中提取关键词
	var existingDomains []models.Domain
	ctx.DB.Where("task_id = ? AND domain LIKE ?", ctx.Task.ID, "%."+domain).Limit(100).Find(&existingDomains)
	
	if len(existingDomains) == 0 {
		return dict
	}
	
	keywords := make(map[string]bool)
	for _, d := range existingDomains {
		// 提取子域名前缀
		subdomain := strings.TrimSuffix(d.Domain, "."+domain)
		parts := strings.Split(subdomain, ".")
		
		for _, part := range parts {
			// 提取数字前的关键词
			base := strings.TrimRight(part, "0123456789-_")
			if base != "" && len(base) > 1 {
				keywords[base] = true
			}
		}
	}
	
	if len(keywords) == 0 {
		return dict
	}
	
	// 基于关键词生成变体
	variations := []string{
		"", "1", "2", "3", "4", "5",
		"01", "02", "03",
		"-1", "-2", "-test", "-dev", "-prod", "-staging",
		"test", "dev", "prod", "uat", "pre",
	}
	
	for keyword := range keywords {
		for _, suffix := range variations {
			candidate := keyword + suffix
			if ds.isValidSubdomain(candidate) {
				dict = append(dict, candidate)
			}
		}
	}
	
	// 添加常见组合
	prefixes := []string{"dev", "test", "staging", "prod", "uat", "pre", "demo", "beta", "alpha", "new", "old"}
	for keyword := range keywords {
		for _, prefix := range prefixes {
			candidate1 := prefix + "-" + keyword
			candidate2 := keyword + "-" + prefix
			candidate3 := prefix + keyword
			
			if ds.isValidSubdomain(candidate1) {
				dict = append(dict, candidate1)
			}
			if ds.isValidSubdomain(candidate2) {
				dict = append(dict, candidate2)
			}
			if ds.isValidSubdomain(candidate3) {
				dict = append(dict, candidate3)
			}
		}
	}
	
	return dict
}

// queryDomainPlugins 查询域名插件
func (ds *DomainScanner) queryDomainPlugins(ctx *ScanContext, domain string) error {
	pluginNames := ctx.Task.Options.DomainPlugins
	if len(pluginNames) == 0 {
		// 默认使用一些免费插件
		pluginNames = []string{"crtsh", "hackertarget"}
		ctx.Logger.Printf("⚠️ No plugins specified in task options, using default: %v", pluginNames)
	}

	ctx.Logger.Printf("=== Domain Plugins Query Started ===")
	ctx.Logger.Printf("Target Domain: %s", domain)
	ctx.Logger.Printf("Selected Plugins: %v (%d)", pluginNames, len(pluginNames))

	// 从数据库获取 API Keys
	apiKeys := ds.loadAPIKeys(ctx)
	ctx.Logger.Printf("Loaded API Keys: %d", len(apiKeys))
	for key := range apiKeys {
		if strings.Contains(key, "fofa") || strings.Contains(key, "hunter") {
			ctx.Logger.Printf("  - %s: %s", key, maskKey(apiKeys[key]))
		}
	}

	// 获取所有可用插件
	allPlugins := GetAvailablePlugins(apiKeys)
	ctx.Logger.Printf("Available Plugins: %d", len(allPlugins))
	pluginMap := make(map[string]DomainPlugin)
	for _, p := range allPlugins {
		pluginMap[p.Name()] = p
		ctx.Logger.Printf("  - %s", p.Name())
	}

	// 用于去重
	foundDomains := make(map[string]bool)

	// 执行插件查询
	for _, pluginName := range pluginNames {
		plugin, exists := pluginMap[pluginName]
		if !exists {
			ctx.Logger.Printf("Plugin not found: %s", pluginName)
			continue
		}

		ctx.Logger.Printf("Running plugin: %s", pluginName)
		domains, err := plugin.Query(domain)
		if err != nil {
			ctx.Logger.Printf("Plugin %s failed: %v", pluginName, err)
			continue
		}

		ctx.Logger.Printf("Plugin %s found %d domains (before filtering)", pluginName, len(domains))

		// 收集需要处理的域名
		var validDomains []string
		for _, d := range domains {
			// 重要：验证域名是否属于目标域名
			if !ds.isSubdomainOf(d, domain) {
				continue
			}
			
			if !foundDomains[d] {
				foundDomains[d] = true
				validDomains = append(validDomains, d)
			}
		}
		
		// 并发处理域名解析和保存
		ctx.Logger.Printf("Plugin %s: processing %d valid domains concurrently", pluginName, len(validDomains))
		validCount := ds.processDomainsInParallel(ctx, validDomains, "plugin:"+pluginName)
		ctx.Logger.Printf("Plugin %s: %d valid subdomains saved", pluginName, validCount)
	}

	ctx.Logger.Printf("Total unique domains from plugins: %d", len(foundDomains))
	return nil
}

// processDomainsInParallel 并发处理域名解析和保存
func (ds *DomainScanner) processDomainsInParallel(ctx *ScanContext, domains []string, source string) int {
	if len(domains) == 0 {
		return 0
	}
	
	// 使用并发处理，提高效率
	workers := 50 // 并发数
	if len(domains) < workers {
		workers = len(domains)
	}
	
	domainChan := make(chan string, len(domains))
	successChan := make(chan int, workers)
	
	var wg sync.WaitGroup
	
	// 启动worker
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localSuccess := 0
			for d := range domainChan {
				// 解析IP
				ips, err := ds.resolveWithRetry(d)
				if err == nil && len(ips) > 0 {
					ds.saveDomain(ctx, d, source, ips[0])
					
					// 保存IP
					for _, ip := range ips {
						ds.saveIPOptimized(ctx, ip, d)
					}
					localSuccess++
				}
			}
			successChan <- localSuccess
		}()
	}
	
	// 发送任务
	for _, d := range domains {
		domainChan <- d
	}
	close(domainChan)
	
	// 等待完成
	wg.Wait()
	close(successChan)
	
	// 统计成功数量
	totalSuccess := 0
	for count := range successChan {
		totalSuccess += count
	}
	
	return totalSuccess
}

// saveDomain 保存域名信息
func (ds *DomainScanner) saveDomain(ctx *ScanContext, domain, source, ip string) {
	d := &models.Domain{
		TaskID: ctx.Task.ID,
		Domain: domain,
		Source: source,
	}
	
	if ip != "" {
		d.IPAddress = ip
	}
	
	// 使用FirstOrCreate避免重复
	ctx.DB.Where("task_id = ? AND domain = ?", ctx.Task.ID, domain).FirstOrCreate(d)
}

// saveIP 保存IP信息
func (ds *DomainScanner) saveIP(ctx *ScanContext, ip, domain string) {
	ipModel := &models.IP{
		TaskID:    ctx.Task.ID,
		IPAddress: ip,
		Domain:    domain,
	}
	
	// 查询IP地理位置
	if location := getIPLocation(ip); location != "" {
		ipModel.Location = location
	}
	
	// 使用FirstOrCreate避免重复
	ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)
}

// saveIPOptimized 优化版IP保存（批量处理时使用，延迟查询地理位置）
func (ds *DomainScanner) saveIPOptimized(ctx *ScanContext, ip, domain string) {
	ipModel := &models.IP{
		TaskID:    ctx.Task.ID,
		IPAddress: ip,
		Domain:    domain,
	}
	
	// 先不查询地理位置，避免API限流
	// 地理位置可以后续批量更新
	
	// 使用FirstOrCreate避免重复
	ctx.DB.Where("task_id = ? AND ip_address = ?", ctx.Task.ID, ip).FirstOrCreate(ipModel)
}

// updateIPLocationsInBatch 批量更新IP地理位置信息
func (ds *DomainScanner) updateIPLocationsInBatch(ctx *ScanContext) {
	// 查询所有没有地理位置的IP
	var ips []models.IP
	ctx.DB.Where("task_id = ? AND (location IS NULL OR location = '')", ctx.Task.ID).Find(&ips)
	
	if len(ips) == 0 {
		ctx.Logger.Printf("No IPs need location update")
		return
	}
	
	ctx.Logger.Printf("Updating location for %d IPs (rate limited to avoid API throttling)", len(ips))
	
	// 限流：每分钟最多45个请求（ip-api.com的免费限制）
	ticker := time.NewTicker(1350 * time.Millisecond) // 约44个请求/分钟
	defer ticker.Stop()
	
	updatedCount := 0
	for i, ip := range ips {
		// 等待限流
		if i > 0 {
			<-ticker.C
		}
		
		// 查询地理位置
		location := getIPLocation(ip.IPAddress)
		if location != "" {
			ctx.DB.Model(&ip).Update("location", location)
			updatedCount++
		}
		
		// 每50个IP记录一次进度
		if (i+1)%50 == 0 {
			ctx.Logger.Printf("IP location update progress: %d/%d", i+1, len(ips))
		}
	}
	
	ctx.Logger.Printf("IP location update completed: %d/%d", updatedCount, len(ips))
}

// isDomain 判断是否为域名
func (ds *DomainScanner) isDomain(target string) bool {
	// 简单判断：包含点且不是IP地址
	if !strings.Contains(target, ".") {
		return false
	}
	
	// 如果能解析为IP，则不是域名
	if net.ParseIP(target) != nil {
		return false
	}
	
	return true
}

// isSubdomainOf 判断 subdomain 是否是 domain 的子域名或等于 domain
func (ds *DomainScanner) isSubdomainOf(subdomain, domain string) bool {
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))
	domain = strings.ToLower(strings.TrimSpace(domain))
	
	// 完全匹配
	if subdomain == domain {
		return true
	}
	
	// 子域名必须以 .domain 结尾
	suffix := "." + domain
	if strings.HasSuffix(subdomain, suffix) {
		return true
	}
	
	return false
}

// loadAPIKeys 从数据库加载 API Keys
func (ds *DomainScanner) loadAPIKeys(ctx *ScanContext) map[string]string {
	apiKeys := make(map[string]string)
	
	// 查询所有 API 类别的设置
	var settings []models.Setting
	ctx.DB.Where("category = ?", "api").Find(&settings)
	
	for _, setting := range settings {
		// 如果是加密的，需要解密
		value := setting.Value
		if setting.IsEncrypted && value != "" {
			decrypted, err := decryptValue(value)
			if err != nil {
				ctx.Logger.Printf("Failed to decrypt %s: %v", setting.Key, err)
				continue
			}
			value = decrypted
		}
		
		// 只有非空值才添加到 apiKeys
		if value != "" {
			apiKeys[setting.Key] = value
		}
	}
	
	return apiKeys
}

// maskKey 遮蔽密钥显示
func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// decryptValue 解密加密的值
func decryptValue(ciphertext string) (string, error) {
	// 获取加密密钥
	key := viper.GetString("encryption.key")
	if key == "" {
		key = "reconmaster-encryption-key-20251" // 正好32字节（与 setting_handler.go 一致）
	}
	
	encryptionKey := []byte(key)
	
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	
	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}
	
	return string(plaintext), nil
}

// generateBigDict 生成内置大字典
func generateBigDict() []string {
	// 常用前缀
	prefixes := []string{
		"www", "mail", "ftp", "webmail", "smtp", "pop", "pop3", "imap", "admin",
		"test", "dev", "stage", "staging", "prod", "production", "demo", "beta", "alpha",
		"api", "app", "mobile", "m", "wap", "web", "www2", "www3",
		"blog", "forum", "bbs", "support", "help", "docs", "doc", "wiki",
		"shop", "store", "cart", "order", "pay", "payment",
		"user", "member", "account", "login", "register", "auth",
		"static", "img", "image", "images", "pic", "pics", "photo", "photos",
		"css", "js", "assets", "cdn", "static", "resource", "resources",
		"video", "videos", "media", "stream", "live",
		"download", "downloads", "upload", "uploads", "file", "files",
		"news", "article", "post", "content",
		"search", "find", "query",
		"data", "db", "database", "mysql", "oracle", "mssql", "redis", "mongodb",
		"cache", "memcache", "memcached",
		"service", "services", "svc",
		"vpn", "proxy", "gateway", "gw",
		"monitor", "monitoring", "dashboard", "console", "panel", "cp", "admin",
		"backup", "bak", "temp", "tmp", "old", "new",
		"log", "logs", "logger", "logging",
		"git", "svn", "hg", "repo", "code",
		"ci", "cd", "jenkins", "travis", "gitlab", "github",
		"docker", "k8s", "kube", "kubernetes",
		"cloud", "public", "private", "internal", "external",
		"oa", "crm", "erp", "hr", "finance",
	}
	
	// 添加数字变体
	var dict []string
	for _, prefix := range prefixes {
		dict = append(dict, prefix)
		// 添加常用数字后缀
		for i := 1; i <= 10; i++ {
			dict = append(dict, fmt.Sprintf("%s%d", prefix, i))
			dict = append(dict, fmt.Sprintf("%s-%d", prefix, i))
			dict = append(dict, fmt.Sprintf("%s%02d", prefix, i))
		}
	}
	
	return dict
}

// getIPLocation 查询IP地理位置（使用免费API）
func getIPLocation(ip string) string {
	// 跳过私有IP
	if isPrivateIP(ip) {
		return "内网IP"
	}
	
	// 使用 ip-api.com 免费API（无需密钥，限制45次/分钟）
	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN&fields=status,country,regionName,city,isp", ip)
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	
	var result struct {
		Status     string `json:"status"`
		Country    string `json:"country"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
	}
	
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	
	if result.Status != "success" {
		return ""
	}
	
	// 组合地理位置信息
	location := result.Country
	if result.RegionName != "" && result.RegionName != result.Country {
		location += " " + result.RegionName
	}
	if result.City != "" && result.City != result.RegionName {
		location += " " + result.City
	}
	if result.ISP != "" {
		location += " (" + result.ISP + ")"
	}
	
	return location
}

// isPrivateIP 判断是否为私有IP
func isPrivateIP(ip string) bool {
	privateIPBlocks := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"169.254.",
		"::1",
		"fc00:",
		"fe80:",
	}
	
	for _, block := range privateIPBlocks {
		if strings.HasPrefix(ip, block) {
			return true
		}
	}
	
	return false
}

