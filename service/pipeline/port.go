package pipeline

import (
	"context"
	"fmt"
	"log"
	"time"

	"moongazing/models"
	"moongazing/scanner/core"
	"moongazing/scanner/fingerprint"
	"go.mongodb.org/mongo-driver/bson"
)

// runCDNDetection 执行CDN检测
func (p *ScanPipeline) runCDNDetection() {
	log.Printf("[Pipeline] Running CDN detection, current subdomains: %d", len(p.discoveredSubdomains))

	// 如果没有子域名结果，使用原始目标
	if len(p.discoveredSubdomains) == 0 {
		log.Printf("[Pipeline] No subdomains discovered, using original targets: %v", p.task.Targets)
		for _, target := range p.task.Targets {
			p.discoveredSubdomains = append(p.discoveredSubdomains, SubdomainInfo{
				Host:   target,
				Domain: target,
				IsCDN:  false,
			})
		}
	}

	// 过滤掉 CDN 的子域名，避免扫描 CDN
	nonCDNHosts := make([]SubdomainInfo, 0)
	for _, sub := range p.discoveredSubdomains {
		if !sub.IsCDN {
			nonCDNHosts = append(nonCDNHosts, sub)
		} else {
			log.Printf("[Pipeline] Skipping CDN host: %s (%s)", sub.Host, sub.CDNName)
		}
	}

	log.Printf("[Pipeline] %d hosts after CDN filter (total subdomains: %d)", len(nonCDNHosts), len(p.discoveredSubdomains))
}

// runPortScan 执行端口扫描
func (p *ScanPipeline) runPortScan() {
	// 确定要扫描的目标
	targets := make([]string, 0)

	log.Printf("[Pipeline] runPortScan starting, discoveredSubdomains count: %d", len(p.discoveredSubdomains))

	if len(p.discoveredSubdomains) > 0 {
		// 扫描发现的子域名
		for _, sub := range p.discoveredSubdomains {
			if !sub.IsCDN {
				targets = append(targets, sub.Host)
				log.Printf("[Pipeline] Adding target from subdomain: %s (IsCDN: %v)", sub.Host, sub.IsCDN)
			}
		}
	} else {
		// 扫描原始目标
		targets = p.task.Targets
		log.Printf("[Pipeline] Using original targets: %v", targets)
	}

	log.Printf("[Pipeline] Running port scan for %d targets: %v", len(targets), targets)

	// 检查 RustScan 是否可用
	if !p.rustScanScanner.IsAvailable() {
		log.Printf("[Pipeline] RustScan not available, skipping port scan")
		return
	}

	for _, target := range targets {
		// full 扫描需要更长的超时时间
		timeout := 10 * time.Minute
		if p.task.Config.PortScanMode == "full" {
			timeout = 30 * time.Minute // full 扫描 30 分钟超时
		}
		ctx, cancel := context.WithTimeout(p.ctx, timeout)

		var scanResult *core.ScanResult
		var err error

		portScanMode := p.task.Config.PortScanMode
		if portScanMode == "" {
			portScanMode = "quick"
		}

		log.Printf("[Pipeline] Port scan mode: %s, timeout: %v", portScanMode, timeout)

		switch portScanMode {
		case "full":
			log.Printf("[Pipeline] Full port scan on %s", target)
			scanResult, err = p.rustScanScanner.FullScan(ctx, target)
		case "top1000":
			log.Printf("[Pipeline] Top1000 port scan on %s", target)
			scanResult, err = p.rustScanScanner.Top1000Scan(ctx, target)
		case "custom":
			customPorts := p.task.Config.PortRange
			if customPorts == "" {
				customPorts = "1-1000"
			}
			log.Printf("[Pipeline] Custom port scan (%s) on %s", customPorts, target)
			scanResult, err = p.rustScanScanner.ScanPorts(ctx, target, customPorts)
		default:
			log.Printf("[Pipeline] Quick port scan on %s", target)
			scanResult, err = p.rustScanScanner.QuickScan(ctx, target)
		}
		cancel()

		if err != nil {
			log.Printf("[Pipeline] RustScan error on %s: %v", target, err)
			continue
		}

		if scanResult == nil {
			continue
		}

		// 保存结果
		for _, port := range scanResult.Ports {
			if port.State == "open" {
				portInfo := PortInfo{
					Host:    target,
					Port:    port.Port,
					Service: port.Service,
					Version: port.Version,
					Banner:  port.Banner,
				}
				p.discoveredPorts = append(p.discoveredPorts, portInfo)

				// 保存到数据库
				p.savePortResult(port, target)
			}
		}
	}

	log.Printf("[Pipeline] Discovered %d open ports", len(p.discoveredPorts))
}

// runFingerprint 执行指纹识别
func (p *ScanPipeline) runFingerprint() {
	log.Printf("[Pipeline] Running fingerprint scan")

	// 对发现的 HTTP/HTTPS 端口进行指纹识别
	for _, port := range p.discoveredPorts {
		if core.IsHTTPPort(port.Port) {
			protocol := "http"
			if port.Port == 443 || port.Port == 8443 {
				protocol = "https"
			}

			url := fmt.Sprintf("%s://%s:%d", protocol, port.Host, port.Port)

			ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
			fpResult := p.fingerprintScanner.ScanFingerprint(ctx, url)
			cancel()

			// 更新端口信息
			fingerprints := make([]string, 0)
			for _, fp := range fpResult.Fingerprints {
				fingerprints = append(fingerprints, fp.Name)
				p.saveFingerprintResult(fp, url)
			}

			// 添加到资产
			asset := AssetInfo{
				Host:        port.Host,
				Port:        port.Port,
				Protocol:    protocol,
				URL:         url,
				Fingerprint: fingerprints,
			}
			p.discoveredAssets = append(p.discoveredAssets, asset)
		}
	}

	log.Printf("[Pipeline] Discovered %d assets", len(p.discoveredAssets))
}

// runAssetMapping 执行资产测绘
func (p *ScanPipeline) runAssetMapping() {
	log.Printf("[Pipeline] Running asset mapping")

	// 对发现的端口进行 HTTP 探测
	for i := range p.discoveredAssets {
		asset := &p.discoveredAssets[i]

		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
		fpResult := p.fingerprintScanner.ScanFingerprint(ctx, asset.URL)
		cancel()

		if fpResult != nil {
			asset.Title = fpResult.Title
			asset.StatusCode = fpResult.StatusCode
			asset.Server = fpResult.Server
		}
	}
}

// savePortResult 保存端口扫描结果
func (p *ScanPipeline) savePortResult(port core.PortResult, host string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypePort,
		Source:      "pipeline",
		Data: bson.M{
			"ip":      host,
			"host":    host,
			"port":    port.Port,
			"service": port.Service,
			"state":   port.State,
			"version": port.Version,
			"banner":  port.Banner,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveFingerprintResult 保存指纹识别结果
func (p *ScanPipeline) saveFingerprintResult(fp fingerprint.Fingerprint, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeService,
		Source:      "pipeline",
		Data: bson.M{
			"target":     target,
			"name":       fp.Name,
			"version":    fp.Version,
			"category":   fp.Category,
			"confidence": fp.Confidence,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}
