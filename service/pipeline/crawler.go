package pipeline

import (
	"context"
	"log"
	"strings"
	"time"

	"moongazing/models"
	"moongazing/scanner/core"
	"moongazing/scanner/webscan"
	"go.mongodb.org/mongo-driver/bson"
)

// runURLScan 执行URL扫描 (使用 Katana)
func (p *ScanPipeline) runURLScan() {
	log.Printf("[Pipeline] Running URL scan with Katana")

	// 获取要爬取的 URL
	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}

	// 如果没有资产，使用原始目标
	if len(urls) == 0 {
		for _, target := range p.task.Targets {
			if strings.HasPrefix(target, "http") {
				urls = append(urls, target)
			} else {
				urls = append(urls, "https://"+target)
			}
		}
	}

	// 使用 Katana 爬取
	if p.katanaScanner.IsAvailable() {
		for _, url := range urls {
			ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.katanaScanner.ExecutionTimeout)*time.Minute)

			result, err := p.katanaScanner.Crawl(ctx, url)
			cancel()

			if err != nil {
				log.Printf("[Pipeline] Katana failed for %s: %v", url, err)
				continue
			}

			for _, crawledURL := range result.URLs {
				urlInfo := URLInfo{
					URL:        crawledURL.URL,
					Method:     crawledURL.Method,
					StatusCode: crawledURL.StatusCode,
					Source:     "katana",
				}
				p.discoveredURLs = append(p.discoveredURLs, urlInfo)
				p.saveURLResult(crawledURL, url)
			}
		}
	}

	log.Printf("[Pipeline] Discovered %d URLs", len(p.discoveredURLs))
}

// runWebCrawler 执行Web爬虫 (使用 Rad)
func (p *ScanPipeline) runWebCrawler() {
	log.Printf("[Pipeline] Running web crawler with Rad")

	if !p.radScanner.IsAvailable() {
		log.Printf("[Pipeline] Rad not available, skipping")
		return
	}

	// 获取要爬取的 URL
	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}

	for _, url := range urls {
		ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.radScanner.ExecutionTimeout)*time.Minute)

		result, err := p.radScanner.Crawl(ctx, url)
		cancel()

		if err != nil {
			log.Printf("[Pipeline] Rad failed for %s: %v", url, err)
			continue
		}

		for _, crawledURL := range result.URLs {
			// 避免重复
			exists := false
			for _, existing := range p.discoveredURLs {
				if existing.URL == crawledURL.URL {
					exists = true
					break
				}
			}

			if !exists {
				urlInfo := URLInfo{
					URL:    crawledURL.URL,
					Method: crawledURL.Method,
					Source: "rad",
				}
				p.discoveredURLs = append(p.discoveredURLs, urlInfo)
			}
		}
	}

	log.Printf("[Pipeline] Total URLs after Rad: %d", len(p.discoveredURLs))
}

// runDirScan 执行目录扫描
func (p *ScanPipeline) runDirScan() {
	log.Printf("[Pipeline] Running directory scan")

	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}

	for _, url := range urls {
		ctx, cancel := context.WithTimeout(p.ctx, 5*time.Minute)
		result := p.contentScanner.QuickDirScan(ctx, url)
		cancel()

		for _, entry := range result.Results {
			p.saveDirScanResult(entry, url)
		}
	}
}

// saveURLResult 保存URL爬取结果
func (p *ScanPipeline) saveURLResult(url webscan.KatanaCrawledURL, source string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeCrawler,
		Source:      source,
		Data: bson.M{
			"url":         url.URL,
			"method":      url.Method,
			"status_code": url.StatusCode,
			"crawler":     source,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveDirScanResult 保存目录扫描结果
func (p *ScanPipeline) saveDirScanResult(entry core.DirEntry, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeDirScan,
		Source:      "pipeline",
		Data: bson.M{
			"target":       target,
			"url":          entry.URL,
			"path":         entry.Path,
			"status":       entry.StatusCode,
			"size":         entry.ContentLength,
			"content_type": entry.ContentType,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}
