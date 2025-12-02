package pipeline

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"moongazing/scanner/fingerprint"
)

// FingerprintModule 指纹识别模块
// 接收端口存活结果，执行HTTP指纹识别，输出资产信息
type FingerprintModule struct {
	BaseModule
	fingerprintScanner *fingerprint.FingerprintScanner
	resultChan         chan interface{}
	concurrency        int
}

// NewFingerprintModule 创建指纹识别模块
func NewFingerprintModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *FingerprintModule {
	if concurrency <= 0 {
		concurrency = 20
	}

	m := &FingerprintModule{
		BaseModule: BaseModule{
			name:       "Fingerprint",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		fingerprintScanner: fingerprint.NewFingerprintScanner(concurrency),
		resultChan:         make(chan interface{}, 500),
		concurrency:        concurrency,
	}
	return m
}

// ModuleRun 运行模块
func (m *FingerprintModule) ModuleRun() error {
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

			// 处理 PortAlive 类型
			portAlive, ok := data.(PortAlive)
			if !ok {
				// 非预期类型，直接传递
				m.resultChan <- data
				continue
			}

			// 先传递端口结果（确保端口数据被收集）
			m.resultChan <- portAlive

			// 跳过空端口（仅域名记录）
			if portAlive.Port == "" {
				continue
			}

			allWg.Add(1)
			go func(pa PortAlive) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.scanFingerprint(pa)
			}(portAlive)
		}
	}
}

// scanFingerprint 执行指纹识别
func (m *FingerprintModule) scanFingerprint(pa PortAlive) {
	// 构建目标URL
	target := m.buildTarget(pa)

	log.Printf("[%s] Scanning fingerprint for %s", m.name, target)

	ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
	defer cancel()

	// 执行指纹扫描
	result := m.fingerprintScanner.ScanFingerprint(ctx, target)

	// 判断是否是有效的HTTP响应（StatusCode > 0 表示成功获取响应）
	if result == nil || result.StatusCode == 0 {
		// 非HTTP服务，尝试端口指纹识别
		m.scanPortFingerprint(pa)
		return
	}

	// 构建 AssetHttp 结果
	asset := AssetHttp{
		Host:       pa.Host,
 		IP:         pa.IP,
		Port:       pa.Port,
		URL:        result.URL,
		Title:      result.Title,
		StatusCode: result.StatusCode,
		Server:     result.Server,
	}

	// 提取技术栈
	if len(result.Technologies) > 0 {
		asset.Technologies = result.Technologies
	}

	// 提取指纹
	for _, fp := range result.Fingerprints {
		asset.Fingerprints = append(asset.Fingerprints, fp.Name)
	}

	log.Printf("[%s] Found HTTP asset: %s (Title: %s, Status: %d, Tech: %v)",
		m.name, target, asset.Title, asset.StatusCode, asset.Technologies)

	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- asset:
	}
}

// scanPortFingerprint 端口指纹识别（非HTTP服务）
func (m *FingerprintModule) scanPortFingerprint(pa PortAlive) {
	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	defer cancel()

	port := stringToInt(pa.Port)
	if port <= 0 {
		return
	}

	result := m.fingerprintScanner.ScanPortFingerprint(ctx, pa.Host, port)
	if result == nil {
		return
	}

	// 构建 AssetOther 结果
	asset := AssetOther{
		Host:    pa.Host,
		IP:      pa.IP,
		Port:    pa.Port,
		Service: result.Service,
		Type:    "other",
		Banner:  result.Banner,
		Version: result.Version,
	}

	log.Printf("[%s] Found non-HTTP asset: %s:%s (%s %s)",
		m.name, pa.Host, pa.Port, result.Service, result.Version)

	select {
	case <-m.ctx.Done():
		return
	case m.resultChan <- asset:
	}
}

// buildTarget 构建扫描目标
func (m *FingerprintModule) buildTarget(pa PortAlive) string {
	port := pa.Port
	host := pa.Host

	// 根据端口判断协议
	switch port {
	case "443", "8443", "9443":
		return fmt.Sprintf("https://%s:%s", host, port)
	case "80":
		return fmt.Sprintf("http://%s", host)
	default:
		// 默认尝试 HTTP
		return fmt.Sprintf("http://%s:%s", host, port)
	}
}

// stringToInt 字符串转整数
func stringToInt(s string) int {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}
