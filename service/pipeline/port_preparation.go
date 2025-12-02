package pipeline

import (
	"context"
	"log"
	"sync"

	"moongazing/scanner/subdomain"
)

// PortScanPreparationModule 端口扫描预处理模块
// 负责在端口扫描前进行CDN检测，决定是否跳过某些目标
type PortScanPreparationModule struct {
	BaseModule
	cdnDetector *subdomain.CDNDetector
	resultChan  chan interface{}
}

// NewPortScanPreparationModule 创建端口扫描预处理模块
func NewPortScanPreparationModule(ctx context.Context, nextModule ModuleRunner) *PortScanPreparationModule {
	m := &PortScanPreparationModule{
		BaseModule: BaseModule{
			name:       "PortScanPreparation",
			ctx:        ctx,
			nextModule: nextModule,
		},
		cdnDetector: subdomain.NewCDNDetector(),
		resultChan:  make(chan interface{}, 1000),
	}
	return m
}

// ModuleRun 运行模块
func (m *PortScanPreparationModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

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

			// 处理 DomainResolve 类型的数据
			domainResolve, ok := data.(DomainResolve)
			if !ok {
				// 非预期类型，直接传递给下一个模块
				log.Printf("[%s] Unexpected data type: %T, passing through, value: %+v", m.name, data, data)
				m.resultChan <- data
				continue
			}

			allWg.Add(1)
			go func(dr DomainResolve) {
				defer allWg.Done()

				// 创建 DomainSkip 结果
				domainSkip := DomainSkip{
					Domain: dr.Domain,
					IP:     dr.IP,
					Skip:   false,
					IsCDN:  false,
				}

				// 执行CDN检测 - 使用域名检测
				cdnResult := m.cdnDetector.DetectCDN(m.ctx, dr.Domain)
				if cdnResult != nil && cdnResult.IsCDN {
					domainSkip.IsCDN = true
					domainSkip.CDN = cdnResult.CDNProvider
					domainSkip.Skip = true // CDN目标跳过端口扫描
					log.Printf("[%s] Detected CDN for %s: %s", m.name, dr.Domain, cdnResult.CDNProvider)
				}

				// 发送结果
				select {
				case <-m.ctx.Done():
					return
				case m.resultChan <- domainSkip:
				}

			}(domainResolve)
		}
	}
}
