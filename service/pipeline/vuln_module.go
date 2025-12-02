package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"moongazing/scanner/vulnscan"
)

// VulnScanModule 漏洞扫描模块
// 接收HTTP资产或URL，执行漏洞扫描，输出漏洞结果
type VulnScanModule struct {
	BaseModule
	vulnScanner *vulnscan.VulnScanner
	resultChan  chan interface{}
	concurrency int
	templates   []string // 指定模板
	severity    []string // 过滤严重级别
	tags        []string // 过滤标签
}

// NewVulnScanModule 创建漏洞扫描模块
func NewVulnScanModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *VulnScanModule {
	if concurrency <= 0 {
		concurrency = 10
	}

	m := &VulnScanModule{
		BaseModule: BaseModule{
			name:       "VulnScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		vulnScanner: vulnscan.NewVulnScanner(concurrency),
		resultChan:  make(chan interface{}, 500),
		concurrency: concurrency,
		severity:    []string{"critical", "high", "medium"}, // 默认只扫描中高危
	}
	return m
}

// SetTemplates 设置要使用的模板
func (m *VulnScanModule) SetTemplates(templates []string) {
	m.templates = templates
}

// SetSeverity 设置要扫描的严重级别
func (m *VulnScanModule) SetSeverity(severity []string) {
	m.severity = severity
}

// SetTags 设置过滤标签
func (m *VulnScanModule) SetTags(tags []string) {
	m.tags = tags
}

// ModuleRun 运行模块
func (m *VulnScanModule) ModuleRun() error {
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
					if vulnResult, ok := result.(VulnResult); ok {
						log.Printf("[%s] Found vulnerability: %s on %s (%s)",
							m.name, vulnResult.Name, vulnResult.Target, vulnResult.Severity)
					}
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

			// 获取扫描目标
			target := m.extractTarget(data)
			if target == "" {
				// 非HTTP资产，直接传递
				m.resultChan <- data
				continue
			}

			// 去重检查
			if m.dupChecker.IsURLDuplicate(target) {
				continue
			}

			allWg.Add(1)
			go func(t string, originalData interface{}) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// 先转发原始数据
				select {
				case <-m.ctx.Done():
					return
				case m.resultChan <- originalData:
				}

				// 执行漏洞扫描
				m.scanVulnerabilities(t)
			}(target, data)
		}
	}
}

// extractTarget 从输入数据中提取目标URL
func (m *VulnScanModule) extractTarget(data interface{}) string {
	switch v := data.(type) {
	case AssetHttp:
		return v.URL
	case UrlResult:
		return v.Output
	case string:
		return v
	default:
		return ""
	}
}

// scanVulnerabilities 执行漏洞扫描
func (m *VulnScanModule) scanVulnerabilities(target string) {
	log.Printf("[%s] Scanning vulnerabilities for %s", m.name, target)

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Minute)
	defer cancel()

	// 获取要扫描的模板
	var templates []*vulnscan.POCTemplate
	if len(m.severity) > 0 {
		for _, sev := range m.severity {
			filtered := m.vulnScanner.FilterTemplatesBySeverity(sev)
			templates = append(templates, filtered...)
		}
	}

	if len(m.tags) > 0 {
		var tagFiltered []*vulnscan.POCTemplate
		for _, tag := range m.tags {
			filtered := m.vulnScanner.FilterTemplatesByTag(tag)
			tagFiltered = append(tagFiltered, filtered...)
		}
		// 如果同时设置了 severity 和 tags，取交集
		if len(templates) > 0 {
			templates = intersectTemplates(templates, tagFiltered)
		} else {
			templates = tagFiltered
		}
	}

	// 执行扫描
	result := m.vulnScanner.ScanVuln(ctx, target, templates)
	if result == nil {
		return
	}

	log.Printf("[%s] Found %d vulnerabilities for %s", m.name, result.TotalFound, target)

	// 发送每个漏洞结果
	for _, vuln := range result.Vulns {
		vulnResult := VulnResult{
			Target:      target,
			VulnID:      vuln.VulnID,
			Name:        vuln.Name,
			Severity:    vuln.Severity,
			Description: vuln.Description,
			Evidence:    vuln.Evidence,
			Remediation: vuln.Remediation,
			Reference:   vuln.Reference,
			MatchedAt:   vuln.MatchedAt,
			Source:      "nuclei",
			Timestamp:   time.Now(),
		}

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- vulnResult:
		}
	}
}

// intersectTemplates 取模板交集
func intersectTemplates(a, b []*vulnscan.POCTemplate) []*vulnscan.POCTemplate {
	m := make(map[string]bool)
	for _, item := range a {
		m[item.ID] = true
	}

	var result []*vulnscan.POCTemplate
	for _, item := range b {
		if m[item.ID] {
			result = append(result, item)
		}
	}
	return result
}

