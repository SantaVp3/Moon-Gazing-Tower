package pipeline

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"moongazing/models"
)

// PipelineConfig 流水线配置
type PipelineConfig struct {
	// 子域名扫描
	SubdomainScan         bool   `json:"subdomain_scan"`
	SubdomainMaxEnumTime  int    `json:"subdomain_max_enum_time"` // 分钟
	SubdomainResolveIP    bool   `json:"subdomain_resolve_ip"`
	SubdomainCheckTakeover bool  `json:"subdomain_check_takeover"`

	// 端口扫描
	PortScan     bool   `json:"port_scan"`
	PortScanMode string `json:"port_scan_mode"` // quick, full, top1000, custom
	PortRange    string `json:"port_range"`     // 自定义端口范围
	SkipCDN      bool   `json:"skip_cdn"`       // 是否跳过 CDN

	// 指纹识别
	Fingerprint bool `json:"fingerprint"`

	// 漏洞扫描
	VulnScan bool `json:"vuln_scan"`

	// 爬虫
	WebCrawler bool `json:"web_crawler"`

	// 目录扫描
	DirScan bool `json:"dir_scan"`

	// 敏感信息检测
	SensitiveScan bool `json:"sensitive_scan"`
}

// DefaultPipelineConfig 默认流水线配置
func DefaultPipelineConfig() *PipelineConfig {
	return &PipelineConfig{
		SubdomainScan:         true,
		SubdomainMaxEnumTime:  10,
		SubdomainResolveIP:    true,
		SubdomainCheckTakeover: false,
		PortScan:              true,
		PortScanMode:          "quick",
		PortRange:             "1-1000",
		SkipCDN:               true,
		Fingerprint:           true,
		VulnScan:              false,
		WebCrawler:            false,
		DirScan:               false,
		SensitiveScan:         false,
	}
}

// StreamingPipeline 流式扫描流水线
type StreamingPipeline struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     *PipelineConfig
	task       *models.Task
	resultChan chan interface{} // 最终结果通道

	// 模块
	subdomainModule   *SubdomainScanModule
	securityModule    *DomainVerifyModule
	portPrepModule    *PortScanPreparationModule
	portScanModule    *PortScanModule
	fingerprintModule *FingerprintModule
	vulnScanModule    *VulnScanModule
	crawlerModule     *CrawlerModule
	dirScanModule     *DirScanModule
	sensitiveModule   *SensitiveModule
	
	// 状态
	running bool
	mu      sync.Mutex
}

// NewStreamingPipeline 创建新的扫描流水线
func NewStreamingPipeline(ctx context.Context, task *models.Task, config *PipelineConfig) *StreamingPipeline {
	if config == nil {
		config = DefaultPipelineConfig()
	}

	pipeCtx, cancel := context.WithCancel(ctx)

	return &StreamingPipeline{
		ctx:        pipeCtx,
		cancel:     cancel,
		config:     config,
		task:       task,
		resultChan: make(chan interface{}, 1000),
	}
}

// Start 启动流水线
func (p *StreamingPipeline) Start(targets []string) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("pipeline already running")
	}
	p.running = true
	p.mu.Unlock()

	log.Printf("[Pipeline] Starting with %d targets, config: %+v", len(targets), p.config)

	// 构建模块链
	if err := p.buildModuleChain(); err != nil {
		return fmt.Errorf("failed to build module chain: %v", err)
	}

	// 获取入口模块
	entryModule := p.getEntryModule()
	if entryModule == nil {
		return fmt.Errorf("no entry module available")
	}

	// 启动流水线处理
	go func() {
		defer close(p.resultChan)
		defer func() {
			p.mu.Lock()
			p.running = false
			p.mu.Unlock()
		}()

		// 启动入口模块（模块会自动链式启动下一个模块）
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := entryModule.ModuleRun(); err != nil {
				log.Printf("[Pipeline] Entry module error: %v", err)
			}
		}()

		// 注入目标到入口模块
		for _, target := range targets {
			select {
			case <-p.ctx.Done():
				log.Printf("[Pipeline] Context cancelled, stopping target injection")
				entryModule.CloseInput()
				wg.Wait()
				return
			case entryModule.GetInput() <- target:
				log.Printf("[Pipeline] Injected target: %s", target)
			}
		}

		// 关闭入口模块输入
		entryModule.CloseInput()
		log.Printf("[Pipeline] All targets injected, waiting for completion")

		// 等待所有模块完成
		wg.Wait()
		log.Printf("[Pipeline] All modules completed")
	}()

	return nil
}

// buildModuleChain 构建模块链
// 链式结构: SubdomainScan -> SubdomainSecurity -> PortScanPreparation -> PortScan -> Fingerprint -> VulnScan -> Crawler -> DirScan -> Sensitive -> ResultCollector
func (p *StreamingPipeline) buildModuleChain() error {
	var lastModule ModuleRunner

	// 从后向前构建模块链

	// 结果收集模块（最后一个模块）
	resultCollector := NewResultCollectorModule(p.ctx, p.resultChan)
	resultCollector.SetInput(make(chan interface{}, 500))
	lastModule = resultCollector

	// 敏感信息检测模块
	if p.config.SensitiveScan {
		p.sensitiveModule = NewSensitiveModule(p.ctx, lastModule, 10)
		p.sensitiveModule.SetInput(make(chan interface{}, 500))
		lastModule = p.sensitiveModule
	}

	// 目录扫描模块
	if p.config.DirScan {
		p.dirScanModule = NewDirScanModule(p.ctx, lastModule, 20, nil)
		p.dirScanModule.SetInput(make(chan interface{}, 500))
		lastModule = p.dirScanModule
	}

	// 爬虫模块
	if p.config.WebCrawler {
		p.crawlerModule = NewCrawlerModule(p.ctx, lastModule, 5, true, false) // 默认使用Katana
		p.crawlerModule.SetInput(make(chan interface{}, 500))
		lastModule = p.crawlerModule
	}

	// 漏洞扫描模块
	if p.config.VulnScan {
		p.vulnScanModule = NewVulnScanModule(p.ctx, lastModule, 10)
		p.vulnScanModule.SetInput(make(chan interface{}, 500))
		lastModule = p.vulnScanModule
	}

	// 指纹识别模块
	if p.config.Fingerprint {
		p.fingerprintModule = NewFingerprintModule(p.ctx, lastModule, 20)
		p.fingerprintModule.SetInput(make(chan interface{}, 500))
		lastModule = p.fingerprintModule
	}

	// 端口扫描模块
	if p.config.PortScan {
		p.portScanModule = NewPortScanModule(p.ctx, lastModule, p.config.PortRange, p.config.PortScanMode)
		p.portScanModule.SetInput(make(chan interface{}, 500))
		lastModule = p.portScanModule
	}

	// CDN检测/端口扫描预处理模块
	if p.config.PortScan && p.config.SkipCDN {
		p.portPrepModule = NewPortScanPreparationModule(p.ctx, lastModule)
		p.portPrepModule.SetInput(make(chan interface{}, 500))
		lastModule = p.portPrepModule
	}

	// 子域名安全检测模块
	if p.config.SubdomainScan {
		p.securityModule = NewDomainVerifyModule(p.ctx, lastModule, 50)
		p.securityModule.SetInput(make(chan interface{}, 500))
		lastModule = p.securityModule
	}

	// 子域名扫描模块（入口模块）
	if p.config.SubdomainScan {
		p.subdomainModule = NewSubdomainScanModule(p.ctx, lastModule, p.config.SubdomainMaxEnumTime, p.config.SubdomainResolveIP)
		p.subdomainModule.SetInput(make(chan interface{}, 500))
		lastModule = p.subdomainModule
	}

	return nil
}

// getEntryModule 获取入口模块
func (p *StreamingPipeline) getEntryModule() ModuleRunner {
	if p.config.SubdomainScan && p.subdomainModule != nil {
		return p.subdomainModule
	}
	if p.config.PortScan && p.portPrepModule != nil {
		return p.portPrepModule
	}
	if p.config.PortScan && p.portScanModule != nil {
		return p.portScanModule
	}
	if p.config.Fingerprint && p.fingerprintModule != nil {
		return p.fingerprintModule
	}
	if p.config.WebCrawler && p.crawlerModule != nil {
		return p.crawlerModule
	}
	return nil
}

// Results 获取结果通道
func (p *StreamingPipeline) Results() <-chan interface{} {
	return p.resultChan
}

// Stop 停止流水线
func (p *StreamingPipeline) Stop() {
	p.cancel()
}

// Wait 等待流水线完成并返回所有结果
func (p *StreamingPipeline) Wait() []interface{} {
	var results []interface{}
	for result := range p.resultChan {
		results = append(results, result)
	}
	return results
}

// ResultCollectorModule 结果收集模块
// 作为流水线的最后一个模块，收集所有结果
type ResultCollectorModule struct {
	BaseModule
	outputChan chan interface{}
}

// NewResultCollectorModule 创建结果收集模块
func NewResultCollectorModule(ctx context.Context, outputChan chan interface{}) *ResultCollectorModule {
	return &ResultCollectorModule{
		BaseModule: BaseModule{
			name:       "ResultCollector",
			ctx:        ctx,
			dupChecker: NewDuplicateChecker(),
		},
		outputChan: outputChan,
	}
}

// ModuleRun 运行模块
func (m *ResultCollectorModule) ModuleRun() error {
	for {
		select {
		case <-m.ctx.Done():
			return nil
		case data, ok := <-m.input:
			if !ok {
				log.Printf("[%s] Input closed, collection complete", m.name)
				return nil
			}

			// 转发到输出通道
			select {
			case <-m.ctx.Done():
				return nil
			case m.outputChan <- data:
			}
		}
	}
}

// RunPipelineScan 便捷函数：运行流水线扫描
func RunPipelineScan(ctx context.Context, targets []string, config *PipelineConfig) ([]interface{}, error) {
	pipeline := NewStreamingPipeline(ctx, nil, config)

	if err := pipeline.Start(targets); err != nil {
		return nil, err
	}

	// 等待完成并收集结果
	results := pipeline.Wait()
	return results, nil
}

// RunQuickScan 快速扫描（子域名 + 快速端口扫描）
func RunQuickScan(ctx context.Context, targets []string) ([]interface{}, error) {
	config := &PipelineConfig{
		SubdomainScan:        true,
		SubdomainMaxEnumTime: 5,
		SubdomainResolveIP:   true,
		PortScan:             true,
		PortScanMode:         "quick",
		SkipCDN:              true,
	}
	return RunPipelineScan(ctx, targets, config)
}

// RunFullScan 完整扫描（子域名 + 全端口扫描）
func RunFullScan(ctx context.Context, targets []string) ([]interface{}, error) {
	config := &PipelineConfig{
		SubdomainScan:        true,
		SubdomainMaxEnumTime: 15,
		SubdomainResolveIP:   true,
		PortScan:             true,
		PortScanMode:         "full",
		SkipCDN:              true,
	}
	return RunPipelineScan(ctx, targets, config)
}

// RunPortOnlyScan 仅端口扫描（不进行子域名枚举）
func RunPortOnlyScan(ctx context.Context, targets []string, portMode string) ([]interface{}, error) {
	// 对于纯端口扫描，需要构建特殊的流水线
	pipeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultChan := make(chan interface{}, 1000)
	resultCollector := NewResultCollectorModule(pipeCtx, resultChan)
	resultCollector.SetInput(make(chan interface{}, 500)) // 初始化输入通道
	
	portScanModule := NewPortScanModule(pipeCtx, resultCollector, "", portMode)
	portScanModule.SetInput(make(chan interface{}, 500)) // 初始化输入通道

	// 启动模块
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := portScanModule.ModuleRun(); err != nil {
			log.Printf("[PortOnlyScan] Module error: %v", err)
		}
	}()

	// 注入目标（转换为 DomainSkip 格式）
	for _, target := range targets {
		ds := DomainSkip{
			Domain: target,
			Skip:   false,
		}
		select {
		case <-pipeCtx.Done():
			break
		case portScanModule.GetInput() <- ds:
		}
	}
	portScanModule.CloseInput()

	// 收集结果
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []interface{}
	for result := range resultChan {
		results = append(results, result)
	}

	return results, nil
}

// PipelineProgress 流水线进度
type PipelineProgress struct {
	CurrentModule string    `json:"current_module"`
	TotalTargets  int       `json:"total_targets"`
	Processed     int       `json:"processed"`
	ResultCount   int       `json:"result_count"`
	StartTime     time.Time `json:"start_time"`
	Elapsed       string    `json:"elapsed"`
}
