package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"moongazing/scanner/webscan"
)

// SensitiveModule 敏感信息检测模块
// 接收HTTP资产或爬取的URL，检测敏感信息
type SensitiveModule struct {
	BaseModule
	contentScanner *webscan.ContentScanner
	resultChan     chan interface{}
	concurrency    int
}

// NewSensitiveModule 创建敏感信息检测模块
func NewSensitiveModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *SensitiveModule {
	if concurrency <= 0 {
		concurrency = 10
	}

	m := &SensitiveModule{
		BaseModule: BaseModule{
			name:       "SensitiveInfo",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		contentScanner: webscan.NewContentScanner(concurrency),
		resultChan:     make(chan interface{}, 500),
		concurrency:    concurrency,
	}
	return m
}

// ModuleRun 运行模块
func (m *SensitiveModule) ModuleRun() error {
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

			// 先传递原始数据到下一个模块
			m.resultChan <- data

			// 获取要扫描的URL
			var targetURL string
			switch v := data.(type) {
			case AssetHttp:
				targetURL = v.URL
			case UrlResult:
				targetURL = v.Output
			default:
				continue
			}

			if targetURL == "" {
				continue
			}

			// URL去重
			if m.dupChecker.IsURLDuplicate(targetURL) {
				continue
			}

			allWg.Add(1)
			go func(url string) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.scanSensitive(url)
			}(targetURL)
		}
	}
}

// scanSensitive 执行敏感信息扫描
func (m *SensitiveModule) scanSensitive(target string) {
	log.Printf("[%s] Scanning sensitive info for %s", m.name, target)

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	result := m.contentScanner.ScanSensitiveInfo(ctx, target)
	if result == nil || result.Found == 0 {
		return
	}

	log.Printf("[%s] Found %d sensitive findings in %s", m.name, result.Found, target)

	// 转换为流水线结果格式
	for _, finding := range result.Findings {
		sensitiveResult := SensitiveInfoResult{
			Target:     result.Target,
			URL:        result.URL,
			Type:       finding.Type,
			Pattern:    finding.Pattern,
			Matches:    finding.Matches,
			Location:   finding.Location,
			Severity:   finding.Severity,
			Confidence: finding.Confidence,
			Source:     "sensitive_scan",
		}

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- sensitiveResult:
		}
	}
}
