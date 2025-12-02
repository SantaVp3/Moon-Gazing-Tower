package pipeline

import (
	"context"
	"log"
	"time"

	"moongazing/models"
	"moongazing/scanner/subdomain"
	"go.mongodb.org/mongo-driver/bson"
)

// runSubdomainScan 执行子域名扫描
// 使用 subfinder (被动收集) + 第三方API (FOFA/Hunter/Quake) + 内置扫描器 (主动爆破)
func (p *ScanPipeline) runSubdomainScan(targets []string) {
	log.Printf("[Pipeline] Running subdomain scan for %d targets", len(targets))

	for _, target := range targets {
		// 跳过 IP 地址
		if isIPAddress(target) {
			p.discoveredSubdomains = append(p.discoveredSubdomains, SubdomainInfo{
				Host:   target,
				Domain: target,
				IPs:    []string{target},
			})
			continue
		}

		// 使用 map 去重
		subdomainSet := make(map[string]bool)

		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Minute)

		// 步骤1: 使用 subfinder 被动收集子域名
		log.Printf("[Pipeline] Step 1: Subfinder passive collection for %s", target)
		subfinderResult, err := p.subfinderScanner.Scan(ctx, target)
		if err != nil {
			log.Printf("[Pipeline] Subfinder error: %v", err)
		}

		// 收集 subfinder 结果
		if subfinderResult != nil {
			subfinderSubs := subfinderResult.GetUniqueSubdomains()
			for _, sub := range subfinderSubs {
				subdomainSet[sub] = true
			}
			log.Printf("[Pipeline] Subfinder found %d subdomains for %s", len(subfinderSubs), target)
		}

		cancel()

		// 步骤1.5: 使用第三方 API 收集子域名 (FOFA, Hunter, Quake, CrtSh)
		if p.thirdpartyManager != nil {
			log.Printf("[Pipeline] Step 1.5: Third-party API collection for %s", target)

			// 获取配置的数据源
			sources := p.task.Config.ThirdPartySources
			if len(sources) == 0 {
				sources = p.thirdpartyManager.GetConfiguredSources()
			}

			log.Printf("[Pipeline] Using third-party sources: %v", sources)

			ctx2, cancel2 := context.WithTimeout(p.ctx, 5*time.Minute)
			thirdpartyResult := p.thirdpartyManager.CollectSubdomains(ctx2, target, sources, 500)
			cancel2()

			if thirdpartyResult != nil {
				for _, sub := range thirdpartyResult.Subdomains {
					subdomainSet[sub] = true
				}
				log.Printf("[Pipeline] Third-party APIs found %d subdomains for %s (sources: %v)",
					thirdpartyResult.TotalFound, target, thirdpartyResult.Sources)
			}
		}

		// 添加原始域名到列表
		subdomainSet[target] = true

		// 转换为切片
		collectedSubdomains := make([]string, 0, len(subdomainSet))
		for sub := range subdomainSet {
			collectedSubdomains = append(collectedSubdomains, sub)
		}

		log.Printf("[Pipeline] Total unique subdomains collected: %d for %s", len(collectedSubdomains), target)

		// 步骤2: 处理结果 - 使用 httpx 丰富子域名信息
		if len(collectedSubdomains) > 0 {
			log.Printf("[Pipeline] Enriching %d subdomains with HTTP info for %s", len(collectedSubdomains), target)

			// 使用 httpx 批量探测子域名，获取 IP、Title、StatusCode、CDN、指纹等信息
			ctx2, cancel2 := context.WithTimeout(p.ctx, 10*time.Minute)
			httpxResults := p.httpxScanner.EnrichSubdomains(ctx2, collectedSubdomains)
			cancel2()

			for _, result := range httpxResults {
				subInfo := SubdomainInfo{
					Host:         result.Host,
					Domain:       target,
					IPs:          result.IPs,
					IsCDN:        result.CDN,
					CDNName:      result.CDNName,
					Title:        result.Title,
					StatusCode:   result.StatusCode,
					WebServer:    result.WebServer,
					Technologies: result.Technologies,
					URL:          result.URL,
				}
				p.discoveredSubdomains = append(p.discoveredSubdomains, subInfo)

				// 保存到数据库（包含完整信息）
				p.saveEnrichedSubdomainResult(subInfo, target)
			}
		} else {
			// 回退：使用内置的子域名字典
			log.Printf("[Pipeline] Fallback to built-in subdomain scan for %s", target)
			ctx2, cancel2 := context.WithTimeout(p.ctx, 5*time.Minute)
			scanResult := p.domainScanner.QuickSubdomainScan(ctx2, target)
			cancel2()
			for _, sub := range scanResult.Subdomains {
				subInfo := SubdomainInfo{
					Host:   sub.FullDomain,
					Domain: target,
					IPs:    sub.IPs,
					CNAMEs: sub.CNAMEs,
					IsCDN:  sub.CDN,
				}
				if sub.CDN {
					subInfo.CDNName = sub.CDNProvider
				}
				p.discoveredSubdomains = append(p.discoveredSubdomains, subInfo)
				p.saveSubdomainResult(sub, target)
			}
		}
	}

	log.Printf("[Pipeline] Discovered %d subdomains total", len(p.discoveredSubdomains))
}

// runSubdomainTakeover 执行子域名接管检测
// 检测子域名是否存在被接管的风险（如 CNAME 指向已失效的云服务）
func (p *ScanPipeline) runSubdomainTakeover() {
	log.Printf("[Pipeline] Running subdomain takeover detection")

	// 获取所有子域名
	subdomains := make([]string, 0)
	if len(p.discoveredSubdomains) > 0 {
		for _, sub := range p.discoveredSubdomains {
			// 跳过 IP 地址
			if !isIPAddress(sub.Host) {
				subdomains = append(subdomains, sub.Host)
			}
		}
	} else {
		// 如果没有发现子域名，使用原始目标
		for _, target := range p.task.Targets {
			if !isIPAddress(target) {
				subdomains = append(subdomains, target)
			}
		}
	}

	if len(subdomains) == 0 {
		log.Printf("[Pipeline] No subdomains to check for takeover")
		return
	}

	log.Printf("[Pipeline] Checking %d subdomains for takeover vulnerabilities", len(subdomains))

	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Minute)
	defer cancel()

	results, err := p.takeoverScanner.ScanBatch(ctx, subdomains)
	if err != nil {
		log.Printf("[Pipeline] Takeover scan error: %v", err)
		return
	}

	vulnerableCount := 0
	for _, result := range results {
		if result.Vulnerable {
			vulnerableCount++
			log.Printf("[Pipeline] Found vulnerable subdomain: %s (Service: %s, CNAME: %s)",
				result.Domain, result.Service, result.CNAME)

			// 保存接管检测结果
			p.saveTakeoverResult(result)
		}
	}

	log.Printf("[Pipeline] Takeover detection completed: %d vulnerable out of %d checked",
		vulnerableCount, len(subdomains))
}

// saveSubdomainResult 保存子域名结果
func (p *ScanPipeline) saveSubdomainResult(sub subdomain.SubdomainResult, domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ips := ""
	if len(sub.IPs) > 0 {
		ips = sub.IPs[0]
	}

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      "pipeline",
		Data: bson.M{
			"subdomain":    sub.Subdomain,
			"domain":       domain,
			"full_domain":  sub.FullDomain,
			"ip":           ips,
			"ips":          sub.IPs,
			"cnames":       sub.CNAMEs,
			"alive":        sub.Alive,
			"cdn":          sub.CDN,
			"cdn_provider": sub.CDNProvider,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveUnverifiedSubdomainResult 保存未验证的子域名结果
func (p *ScanPipeline) saveUnverifiedSubdomainResult(subdomain, domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      "subfinder",
		Data: bson.M{
			"subdomain":   subdomain,
			"domain":      domain,
			"full_domain": subdomain,
			"verified":    false,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveEnrichedSubdomainResult 保存丰富后的子域名结果（包含 IP、Title、StatusCode、CDN、指纹等）
func (p *ScanPipeline) saveEnrichedSubdomainResult(subInfo SubdomainInfo, domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := ""
	if len(subInfo.IPs) > 0 {
		ip = subInfo.IPs[0]
	}

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeSubdomain,
		Source:      "httpx",
		Data: bson.M{
			"subdomain":    subInfo.Host,
			"domain":       domain,
			"full_domain":  subInfo.Host,
			"ip":           ip,
			"ips":          subInfo.IPs,
			"cdn":          subInfo.IsCDN,
			"cdn_provider": subInfo.CDNName,
			"title":        subInfo.Title,
			"status_code":  subInfo.StatusCode,
			"web_server":   subInfo.WebServer,
			"fingerprint":  subInfo.Technologies,
			"url":          subInfo.URL,
			"is_alive":     subInfo.StatusCode > 0,
			"verified":     true,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveTakeoverResult 保存子域名接管检测结果
func (p *ScanPipeline) saveTakeoverResult(result *subdomain.TakeoverResult) {
	p.mu.Lock()
	defer p.mu.Unlock()

	scanResult := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeTakeover,
		Source:      "takeover_scanner",
		Data: bson.M{
			"subdomain":    result.Domain,
			"cname":        result.CNAME,
			"provider":     result.Service,
			"vulnerable":   result.Vulnerable,
			"fingerprints": result.Fingerprints,
			"reason":       result.Reason,
			"discussion":   result.Discussion,
			"severity":     "high", // 子域名接管通常是高危漏洞
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResult(&scanResult)
	p.totalResults++
}
