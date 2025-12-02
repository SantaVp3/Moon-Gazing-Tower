package pipeline

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"moongazing/scanner/core"
	"moongazing/scanner/portscan"
)

// PortScanModule 端口扫描模块
// 接收预处理后的域名，执行端口扫描，输出存活端口
type PortScanModule struct {
	BaseModule
	rustScanner *portscan.RustScanScanner
	resultChan  chan interface{}
	portRange   string
	scanMode    string
}

// NewPortScanModule 创建端口扫描模块
func NewPortScanModule(ctx context.Context, nextModule ModuleRunner, portRange, scanMode string) *PortScanModule {
	if scanMode == "" {
		scanMode = "quick"
	}
	if portRange == "" {
		portRange = "1-1000"
	}

	m := &PortScanModule{
		BaseModule: BaseModule{
			name:       "PortScan",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		rustScanner: portscan.NewRustScanScanner(),
		resultChan:  make(chan interface{}, 1000),
		portRange:   portRange,
		scanMode:    scanMode,
	}
	return m
}

// ModuleRun 运行模块
func (m *PortScanModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	// 检查 RustScan 是否可用
	if !m.rustScanner.IsAvailable() {
		log.Printf("[%s] RustScan not available, skipping port scan", m.name)
		// 直接关闭下一个模块
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
		return nil
	}

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

	// 结果处理协程 - 去重并发送到下一个模块
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			if portAlive, ok := result.(PortAlive); ok {
				// 去重检查
				if portAlive.Port != "" && m.dupChecker.IsPortDuplicate(portAlive.Host, portAlive.Port) {
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

			// 处理不同类型的输入
			var domainSkip DomainSkip
			switch v := data.(type) {
			case DomainSkip:
				domainSkip = v
			case string:
				// 支持直接传入域名字符串
				domainSkip = DomainSkip{
					Domain: v,
					Skip:   false,
				}
			case DomainResolve:
				// 支持 DomainResolve 类型
				domainSkip = DomainSkip{
					Domain: v.Domain,
					IP:     v.IP,
					Skip:   false,
				}
			default:
				// 非预期类型，直接传递
				m.resultChan <- data
				continue
			}

			// 无论是否扫描，都发送一个基础记录
			baseResult := PortAlive{
				Host: domainSkip.Domain,
				IP:   "",
				Port: "",
			}
			m.resultChan <- baseResult

			// 如果需要跳过（如CDN），不进行端口扫描
			if domainSkip.Skip {
				log.Printf("[%s] Skipping %s (CDN: %s)", m.name, domainSkip.Domain, domainSkip.CDN)
				continue
			}

			allWg.Add(1)
			go func(ds DomainSkip) {
				defer allWg.Done()
				m.scanPorts(ds)
			}(domainSkip)
		}
	}
}

// scanPorts 执行端口扫描
func (m *PortScanModule) scanPorts(ds DomainSkip) {
	log.Printf("[%s] Starting port scan for %s (mode: %s)", m.name, ds.Domain, m.scanMode)

	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
	defer cancel()

	var scanResult *core.ScanResult
	var err error

	// 根据扫描模式选择扫描方式
	switch m.scanMode {
	case "full":
		scanResult, err = m.rustScanner.FullScan(ctx, ds.Domain)
	case "top1000":
		scanResult, err = m.rustScanner.Top1000Scan(ctx, ds.Domain)
	case "custom":
		scanResult, err = m.rustScanner.ScanPorts(ctx, ds.Domain, m.portRange)
	default: // quick
		scanResult, err = m.rustScanner.QuickScan(ctx, ds.Domain)
	}

	if err != nil {
		log.Printf("[%s] RustScan error for %s: %v", m.name, ds.Domain, err)
		return
	}

	if scanResult == nil {
		return
	}

	// 发送扫描结果
	for _, port := range scanResult.Ports {
		if port.State != "open" {
			continue
		}

		ip := ""
		if len(ds.IP) > 0 {
			ip = ds.IP[0]
		}

		result := PortAlive{
			Host:    ds.Domain,
			IP:      ip,
			Port:    intToString(port.Port),
			Service: port.Service,
		}

		log.Printf("[%s] Found open port: %s:%d (%s)", m.name, ds.Domain, port.Port, port.Service)

		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- result:
		}
	}

	log.Printf("[%s] Port scan completed for %s, found %d ports", m.name, ds.Domain, len(scanResult.Ports))
}

// intToString 整数转字符串
func intToString(n int) string {
	return fmt.Sprintf("%d", n)
}
