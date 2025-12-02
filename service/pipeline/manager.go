package pipeline

import (
	"context"
	"log"
	"sync"
)

// ModuleRunner 模块运行器接口
// 每个扫描模块都需要实现此接口
type ModuleRunner interface {
	// ModuleRun 运行模块
	ModuleRun() error
	// SetInput 设置输入通道
	SetInput(ch chan interface{})
	// GetInput 获取输入通道
	GetInput() chan interface{}
	// CloseInput 关闭输入通道
	CloseInput()
	// GetName 获取模块名称
	GetName() string
}

// PipelineManager 流水线管理器
// 负责协调各个扫描模块的执行
type PipelineManager struct {
	ctx        context.Context
	cancel     context.CancelFunc
	wg         *sync.WaitGroup
	inputChans map[string]chan interface{}
	modules    []ModuleRunner
	stats      *PipelineStats
	statsMu    sync.Mutex
}

// NewPipelineManager 创建流水线管理器
func NewPipelineManager(ctx context.Context) *PipelineManager {
	ctx, cancel := context.WithCancel(ctx)
	return &PipelineManager{
		ctx:        ctx,
		cancel:     cancel,
		wg:         &sync.WaitGroup{},
		inputChans: make(map[string]chan interface{}),
		modules:    make([]ModuleRunner, 0),
		stats:      &PipelineStats{},
	}
}

// RegisterModule 注册模块
func (pm *PipelineManager) RegisterModule(name string, module ModuleRunner) {
	pm.modules = append(pm.modules, module)
	ch := make(chan interface{}, 500) // 缓冲通道
	pm.inputChans[name] = ch
	module.SetInput(ch)
}

// GetInputChan 获取指定模块的输入通道
func (pm *PipelineManager) GetInputChan(name string) chan interface{} {
	return pm.inputChans[name]
}

// Start 启动流水线
func (pm *PipelineManager) Start() {
	log.Printf("[PipelineManager] Starting pipeline with %d modules", len(pm.modules))

	// 启动所有模块
	for _, module := range pm.modules {
		pm.wg.Add(1)
		go func(m ModuleRunner) {
			defer pm.wg.Done()
			log.Printf("[PipelineManager] Starting module: %s", m.GetName())
			if err := m.ModuleRun(); err != nil {
				log.Printf("[PipelineManager] Module %s error: %v", m.GetName(), err)
			}
			log.Printf("[PipelineManager] Module %s completed", m.GetName())
		}(module)
	}
}

// Wait 等待流水线完成
func (pm *PipelineManager) Wait() {
	pm.wg.Wait()
	log.Printf("[PipelineManager] All modules completed")
}

// Stop 停止流水线
func (pm *PipelineManager) Stop() {
	pm.cancel()
	// 关闭所有输入通道
	for name, ch := range pm.inputChans {
		log.Printf("[PipelineManager] Closing input channel for %s", name)
		close(ch)
	}
}

// Context 获取上下文
func (pm *PipelineManager) Context() context.Context {
	return pm.ctx
}

// UpdateStats 更新统计信息
func (pm *PipelineManager) UpdateStats(fn func(stats *PipelineStats)) {
	pm.statsMu.Lock()
	defer pm.statsMu.Unlock()
	fn(pm.stats)
}

// GetStats 获取统计信息
func (pm *PipelineManager) GetStats() PipelineStats {
	pm.statsMu.Lock()
	defer pm.statsMu.Unlock()
	return *pm.stats
}

// DuplicateChecker 去重检查器
// 用于在任务内去重
type DuplicateChecker struct {
	subdomains sync.Map // map[string]bool
	ports      sync.Map // map[string]bool
	urls       sync.Map // map[string]bool
}

// NewDuplicateChecker 创建去重检查器
func NewDuplicateChecker() *DuplicateChecker {
	return &DuplicateChecker{}
}

// IsSubdomainDuplicate 检查子域名是否重复
func (dc *DuplicateChecker) IsSubdomainDuplicate(host string) bool {
	_, loaded := dc.subdomains.LoadOrStore(host, true)
	return loaded
}

// IsPortDuplicate 检查端口是否重复
func (dc *DuplicateChecker) IsPortDuplicate(host, port string) bool {
	key := host + ":" + port
	_, loaded := dc.ports.LoadOrStore(key, true)
	return loaded
}

// IsURLDuplicate 检查URL是否重复
func (dc *DuplicateChecker) IsURLDuplicate(url string) bool {
	_, loaded := dc.urls.LoadOrStore(url, true)
	return loaded
}

// BaseModule 基础模块
// 提供通用的模块功能
type BaseModule struct {
	name       string
	input      chan interface{}
	nextModule ModuleRunner
	ctx        context.Context
	dupChecker *DuplicateChecker
}

// SetInput 设置输入通道
func (m *BaseModule) SetInput(ch chan interface{}) {
	m.input = ch
}

// GetInput 获取输入通道
func (m *BaseModule) GetInput() chan interface{} {
	return m.input
}

// CloseInput 关闭输入通道
func (m *BaseModule) CloseInput() {
	if m.input != nil {
		close(m.input)
	}
}

// GetName 获取模块名称
func (m *BaseModule) GetName() string {
	return m.name
}

// SetNextModule 设置下一个模块
func (m *BaseModule) SetNextModule(next ModuleRunner) {
	m.nextModule = next
}

// SendToNext 发送数据到下一个模块
func (m *BaseModule) SendToNext(data interface{}) {
	if m.nextModule != nil {
		select {
		case <-m.ctx.Done():
			return
		case m.nextModule.GetInput() <- data:
		}
	}
}
