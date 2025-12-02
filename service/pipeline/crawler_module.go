package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"moongazing/scanner/webscan"
)

// CrawlerModule URL爬虫模块
// 接收HTTP资产，执行URL爬虫，输出发现的URL
type CrawlerModule struct {
	BaseModule
	katanaScanner *webscan.KatanaScanner
	radScanner    *webscan.RadScanner
	resultChan    chan interface{}
	concurrency   int
	useKatana     bool
	useRad        bool
	crawlDepth    int
}

// NewCrawlerModule 创建爬虫模块
func NewCrawlerModule(ctx context.Context, nextModule ModuleRunner, concurrency int, useKatana, useRad bool) *CrawlerModule {
	if concurrency <= 0 {
		concurrency = 5
	}

	m := &CrawlerModule{
		BaseModule: BaseModule{
			name:       "Crawler",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		katanaScanner: webscan.NewKatanaScanner(),
		radScanner:    webscan.NewRadScanner(),
		resultChan:    make(chan interface{}, 1000),
		concurrency:   concurrency,
		useKatana:     useKatana,
		useRad:        useRad,
		crawlDepth:    3,
	}
	return m
}

// SetCrawlDepth 设置爬取深度
func (m *CrawlerModule) SetCrawlDepth(depth int) {
	if depth > 0 {
		m.crawlDepth = depth
		m.katanaScanner.Depth = depth
	}
}

// ModuleRun 运行模块
func (m *CrawlerModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 并发控制
	sem := make(chan struct{}, m.concurrency)

	// 检查爬虫工具是否可用
	katanaAvailable := m.useKatana && m.katanaScanner.IsAvailable()
	radAvailable := m.useRad && m.radScanner.IsAvailable()

	if !katanaAvailable && !radAvailable {
		log.Printf("[%s] No crawler available, skipping", m.name)
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
		return nil
	}

	log.Printf("[%s] Starting with Katana=%v, Rad=%v", m.name, katanaAvailable, radAvailable)

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
			if urlResult, ok := result.(UrlResult); ok {
				// URL去重
				if m.dupChecker.IsURLDuplicate(urlResult.Output) {
					continue
				}
			}

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

			// 处理 AssetHttp 类型
			asset, ok := data.(AssetHttp)
			if !ok {
				// 非预期类型，直接传递
				m.resultChan <- data
				continue
			}

			// 先传递 AssetHttp 结果（确保 Web 服务数据被收集）
			m.resultChan <- asset

			// 只处理有效的HTTP资产
			if asset.URL == "" {
				continue
			}

			allWg.Add(1)
			go func(a AssetHttp) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.crawlTarget(a, katanaAvailable, radAvailable)
			}(asset)
		}
	}
}

// crawlTarget 爬取目标
func (m *CrawlerModule) crawlTarget(asset AssetHttp, useKatana, useRad bool) {
	target := asset.URL

	log.Printf("[%s] Crawling %s", m.name, target)

	// 使用 Katana 爬取
	if useKatana {
		m.crawlWithKatana(target, asset)
	}

	// 使用 Rad 爬取（可以同时使用，发现不同URL）
	if useRad {
		m.crawlWithRad(target, asset)
	}
}

// crawlWithKatana 使用Katana爬取
func (m *CrawlerModule) crawlWithKatana(target string, asset AssetHttp) {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
	defer cancel()

	result, err := m.katanaScanner.Crawl(ctx, target)
	if err != nil {
		log.Printf("[%s] Katana error for %s: %v", m.name, target, err)
		return
	}

	if result == nil {
		return
	}

	log.Printf("[%s] Katana found %d URLs for %s", m.name, len(result.URLs), target)

	for _, url := range result.URLs {
		urlResult := UrlResult{
			Input:      target,
			Output:     url.URL,
			Source:     "katana",
			Method:     url.Method,
			StatusCode: url.StatusCode,
		}

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- urlResult:
		}
	}
}

// crawlWithRad 使用Rad爬取
func (m *CrawlerModule) crawlWithRad(target string, asset AssetHttp) {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
	defer cancel()

	result, err := m.radScanner.Crawl(ctx, target)
	if err != nil {
		log.Printf("[%s] Rad error for %s: %v", m.name, target, err)
		return
	}

	if result == nil {
		return
	}

	log.Printf("[%s] Rad found %d URLs for %s", m.name, len(result.URLs), target)

	for _, url := range result.URLs {
		urlResult := UrlResult{
			Input:  target,
			Output: url.URL,
			Source: "rad",
			Method: url.Method,
		}

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- urlResult:
		}
	}
}

// DirScanModule 目录扫描模块
// 接收HTTP资产，执行目录爆破，输出发现的URL
type DirScanModule struct {
	BaseModule
	contentScanner *webscan.ContentScanner
	resultChan     chan interface{}
	concurrency    int
	wordlist       []string
}

// NewDirScanModule 创建目录扫描模块
func NewDirScanModule(ctx context.Context, nextModule ModuleRunner, concurrency int, wordlist []string) *DirScanModule {
	if concurrency <= 0 {
		concurrency = 20
	}

	m := &DirScanModule{
		BaseModule: BaseModule{
			name:       "DirScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		contentScanner: webscan.NewContentScanner(concurrency),
		resultChan:     make(chan interface{}, 500),
		concurrency:    concurrency,
		wordlist:       wordlist,
	}
	return m
}

// ModuleRun 运行模块
func (m *DirScanModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 并发控制
	sem := make(chan struct{}, m.concurrency)

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

			// 处理 AssetHttp 类型
			asset, ok := data.(AssetHttp)
			if !ok {
				m.resultChan <- data
				continue
			}

			if asset.URL == "" {
				continue
			}

			allWg.Add(1)
			go func(a AssetHttp) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.scanDirectory(a)
			}(asset)
		}
	}
}

// scanDirectory 执行目录扫描
func (m *DirScanModule) scanDirectory(asset AssetHttp) {
	target := asset.URL

	log.Printf("[%s] Scanning directories for %s", m.name, target)

	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Minute)
	defer cancel()

	result := m.contentScanner.DirBrute(ctx, target, m.wordlist, nil)
	if result == nil {
		log.Printf("[%s] Directory scan returned nil for %s", m.name, target)
		return
	}

	log.Printf("[%s] Found %d paths for %s", m.name, len(result.Results), target)

	for _, entry := range result.Results {
		if entry.StatusCode >= 200 && entry.StatusCode < 400 {
			urlResult := UrlResult{
				Input:  target,
				Output: entry.URL,
				Source: "dirscan",
			}

			select {
			case <-m.ctx.Done():
				return
			case m.resultChan <- urlResult:
			}
		}
	}
}
