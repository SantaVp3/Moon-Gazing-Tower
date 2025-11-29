package thirdparty

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// APIManager 第三方 API 统一管理器
type APIManager struct {
	Fofa           *FofaClient
	Hunter         *HunterClient
	Quake          *QuakeClient
	CrtSh          *CrtShClient
	SecurityTrails *SecurityTrailsClient
	config         *APIConfig // 保存配置信息
}

// APIConfig 第三方 API 配置
type APIConfig struct {
	FofaEmail          string `json:"fofa_email" yaml:"fofa_email"`
	FofaKey            string `json:"fofa_key" yaml:"fofa_key"`
	HunterKey          string `json:"hunter_key" yaml:"hunter_key"`
	QuakeKey           string `json:"quake_key" yaml:"quake_key"`
	SecurityTrailsKey  string `json:"securitytrails_key" yaml:"securitytrails_key"`
}

// UnifiedAsset 统一资产格式
type UnifiedAsset struct {
	Host       string   `json:"host"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Protocol   string   `json:"protocol"`
	Domain     string   `json:"domain"`
	Title      string   `json:"title"`
	Server     string   `json:"server"`
	Country    string   `json:"country"`
	City       string   `json:"city"`
	ISP        string   `json:"isp"`
	Banner     string   `json:"banner"`
	Cert       string   `json:"cert"`
	Components []string `json:"components,omitempty"`
	Source     string   `json:"source"` // fofa, hunter, quake, crtsh, securitytrails
	UpdateTime string   `json:"update_time,omitempty"`
}

// SubdomainResult 子域名收集结果
type SubdomainResult struct {
	Domain       string         `json:"domain"`
	TotalFound   int            `json:"total_found"`
	Subdomains   []string       `json:"subdomains"`
	Sources      map[string]int `json:"sources"` // 每个来源发现的数量
	Assets       []UnifiedAsset `json:"assets,omitempty"`
	Duration     string         `json:"duration"`
}

// NewAPIManager 创建 API 管理器
func NewAPIManager(config *APIConfig) *APIManager {
	manager := &APIManager{
		CrtSh: NewCrtShClient(), // crt.sh 免费，不需要配置
	}

	if config != nil {
		if config.FofaEmail != "" && config.FofaKey != "" {
			manager.Fofa = NewFofaClient(config.FofaEmail, config.FofaKey)
		}
		if config.HunterKey != "" {
			manager.Hunter = NewHunterClient(config.HunterKey)
		}
		if config.QuakeKey != "" {
			manager.Quake = NewQuakeClient(config.QuakeKey)
		}
		if config.SecurityTrailsKey != "" {
			manager.SecurityTrails = NewSecurityTrailsClient(config.SecurityTrailsKey)
		}
	}

	return manager
}

// UpdateConfig 更新配置
func (m *APIManager) UpdateConfig(config *APIConfig) {
	// 保存配置
	if m.config == nil {
		m.config = &APIConfig{}
	}
	
	// 更新非空字段
	if config.FofaEmail != "" {
		m.config.FofaEmail = config.FofaEmail
	}
	if config.FofaKey != "" {
		m.config.FofaKey = config.FofaKey
	}
	if config.HunterKey != "" {
		m.config.HunterKey = config.HunterKey
	}
	if config.QuakeKey != "" {
		m.config.QuakeKey = config.QuakeKey
	}
	if config.SecurityTrailsKey != "" {
		m.config.SecurityTrailsKey = config.SecurityTrailsKey
	}
	
	// 重建客户端
	if m.config.FofaEmail != "" && m.config.FofaKey != "" {
		m.Fofa = NewFofaClient(m.config.FofaEmail, m.config.FofaKey)
	}
	if m.config.HunterKey != "" {
		m.Hunter = NewHunterClient(m.config.HunterKey)
	}
	if m.config.QuakeKey != "" {
		m.Quake = NewQuakeClient(m.config.QuakeKey)
	}
	if m.config.SecurityTrailsKey != "" {
		m.SecurityTrails = NewSecurityTrailsClient(m.config.SecurityTrailsKey)
	}
}

// GetConfig 获取当前配置（脱敏）
func (m *APIManager) GetConfig() *APIConfig {
	if m.config == nil {
		return &APIConfig{}
	}
	// 返回脱敏后的配置
	return &APIConfig{
		FofaEmail:         m.config.FofaEmail,
		FofaKey:           maskKey(m.config.FofaKey),
		HunterKey:         maskKey(m.config.HunterKey),
		QuakeKey:          maskKey(m.config.QuakeKey),
		SecurityTrailsKey: maskKey(m.config.SecurityTrailsKey),
	}
}

// GetRawConfig 获取原始配置（不脱敏，内部使用）
func (m *APIManager) GetRawConfig() *APIConfig {
	if m.config == nil {
		return &APIConfig{}
	}
	return m.config
}

// maskKey 对密钥进行脱敏处理
func maskKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// GetConfiguredSources 获取已配置的数据源
func (m *APIManager) GetConfiguredSources() []string {
	sources := []string{"crtsh"} // crt.sh 始终可用

	if m.Fofa != nil && m.Fofa.IsConfigured() {
		sources = append(sources, "fofa")
	}
	if m.Hunter != nil && m.Hunter.IsConfigured() {
		sources = append(sources, "hunter")
	}
	if m.Quake != nil && m.Quake.IsConfigured() {
		sources = append(sources, "quake")
	}
	if m.SecurityTrails != nil && m.SecurityTrails.IsConfigured() {
		sources = append(sources, "securitytrails")
	}

	return sources
}

// CollectSubdomains 从多个数据源收集子域名
func (m *APIManager) CollectSubdomains(ctx context.Context, domain string, sources []string, maxResults int) *SubdomainResult {
	result := &SubdomainResult{
		Domain:     domain,
		Subdomains: []string{},
		Sources:    make(map[string]int),
		Assets:     []UnifiedAsset{},
	}

	if len(sources) == 0 {
		sources = m.GetConfiguredSources()
	}

	if maxResults <= 0 {
		maxResults = 100
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	subdomainSet := make(map[string]bool)

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			var subdomains []string
			var assets []UnifiedAsset
			var err error

			switch src {
			case "fofa":
				if m.Fofa != nil && m.Fofa.IsConfigured() {
					fofaAssets, e := m.Fofa.SearchSubdomains(ctx, domain, maxResults)
					if e == nil {
						for _, a := range fofaAssets {
							assets = append(assets, m.convertFofaAsset(a))
							if a.Domain != "" {
								subdomains = append(subdomains, a.Domain)
							}
							if a.Host != "" && strings.Contains(a.Host, domain) {
								subdomains = append(subdomains, extractDomainFromHost(a.Host))
							}
						}
					}
					err = e
				}

			case "hunter":
				if m.Hunter != nil && m.Hunter.IsConfigured() {
					hunterAssets, e := m.Hunter.SearchSubdomains(ctx, domain, maxResults)
					if e == nil {
						for _, a := range hunterAssets {
							assets = append(assets, m.convertHunterAsset(a))
							if a.Domain != "" {
								subdomains = append(subdomains, a.Domain)
							}
						}
					}
					err = e
				}

			case "quake":
				if m.Quake != nil && m.Quake.IsConfigured() {
					quakeAssets, e := m.Quake.SearchSubdomains(ctx, domain, maxResults)
					if e == nil {
						for _, a := range quakeAssets {
							assets = append(assets, m.convertQuakeAsset(a))
							if a.Domain != "" {
								subdomains = append(subdomains, a.Domain)
							}
							if a.Hostname != "" {
								subdomains = append(subdomains, a.Hostname)
							}
						}
					}
					err = e
				}

			case "crtsh":
				subdomains, err = m.CrtSh.SearchSubdomains(ctx, domain)

			case "securitytrails":
				if m.SecurityTrails != nil && m.SecurityTrails.IsConfigured() {
					subdomains, err = m.SecurityTrails.SearchSubdomains(ctx, domain)
				}
			}

			if err != nil {
				return // 忽略单个源的错误，继续其他源
			}

			mu.Lock()
			defer mu.Unlock()

			count := 0
			for _, sub := range subdomains {
				sub = strings.ToLower(strings.TrimSpace(sub))
				// 过滤通配符和无效域名
				if sub == "" || strings.HasPrefix(sub, "*") || !strings.Contains(sub, domain) {
					continue
				}
				if !subdomainSet[sub] {
					subdomainSet[sub] = true
					result.Subdomains = append(result.Subdomains, sub)
					count++
				}
			}
			result.Sources[src] = count
			result.Assets = append(result.Assets, assets...)

		}(source)
	}

	wg.Wait()

	// 排序
	sort.Strings(result.Subdomains)
	result.TotalFound = len(result.Subdomains)

	return result
}

// SearchByIP 根据 IP 搜索资产
func (m *APIManager) SearchByIP(ctx context.Context, ip string, sources []string, maxResults int) []UnifiedAsset {
	if len(sources) == 0 {
		sources = m.GetConfiguredSources()
	}

	if maxResults <= 0 {
		maxResults = 100
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allAssets []UnifiedAsset

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			var assets []UnifiedAsset

			switch src {
			case "fofa":
				if m.Fofa != nil && m.Fofa.IsConfigured() {
					fofaAssets, err := m.Fofa.SearchByIP(ctx, ip, maxResults)
					if err == nil {
						for _, a := range fofaAssets {
							assets = append(assets, m.convertFofaAsset(a))
						}
					}
				}

			case "hunter":
				if m.Hunter != nil && m.Hunter.IsConfigured() {
					hunterAssets, err := m.Hunter.SearchByIP(ctx, ip, maxResults)
					if err == nil {
						for _, a := range hunterAssets {
							assets = append(assets, m.convertHunterAsset(a))
						}
					}
				}

			case "quake":
				if m.Quake != nil && m.Quake.IsConfigured() {
					quakeAssets, err := m.Quake.SearchByIP(ctx, ip, maxResults)
					if err == nil {
						for _, a := range quakeAssets {
							assets = append(assets, m.convertQuakeAsset(a))
						}
					}
				}
			}

			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()

		}(source)
	}

	wg.Wait()
	return allAssets
}

// SearchByCert 根据证书关键字搜索
func (m *APIManager) SearchByCert(ctx context.Context, keyword string, sources []string, maxResults int) []UnifiedAsset {
	if len(sources) == 0 {
		sources = m.GetConfiguredSources()
	}

	if maxResults <= 0 {
		maxResults = 100
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allAssets []UnifiedAsset

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			var assets []UnifiedAsset

			switch src {
			case "fofa":
				if m.Fofa != nil && m.Fofa.IsConfigured() {
					fofaAssets, err := m.Fofa.SearchCert(ctx, keyword, maxResults)
					if err == nil {
						for _, a := range fofaAssets {
							assets = append(assets, m.convertFofaAsset(a))
						}
					}
				}

			case "quake":
				if m.Quake != nil && m.Quake.IsConfigured() {
					quakeAssets, err := m.Quake.SearchByCert(ctx, keyword, maxResults)
					if err == nil {
						for _, a := range quakeAssets {
							assets = append(assets, m.convertQuakeAsset(a))
						}
					}
				}
			}

			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()

		}(source)
	}

	wg.Wait()
	return allAssets
}

// SearchByIconHash 根据图标哈希搜索
func (m *APIManager) SearchByIconHash(ctx context.Context, hash string, sources []string, maxResults int) []UnifiedAsset {
	if len(sources) == 0 {
		sources = m.GetConfiguredSources()
	}

	if maxResults <= 0 {
		maxResults = 100
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allAssets []UnifiedAsset

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			var assets []UnifiedAsset

			switch src {
			case "fofa":
				if m.Fofa != nil && m.Fofa.IsConfigured() {
					fofaAssets, err := m.Fofa.SearchByIconHash(ctx, hash, maxResults)
					if err == nil {
						for _, a := range fofaAssets {
							assets = append(assets, m.convertFofaAsset(a))
						}
					}
				}

			case "quake":
				if m.Quake != nil && m.Quake.IsConfigured() {
					quakeAssets, err := m.Quake.SearchByFaviconHash(ctx, hash, maxResults)
					if err == nil {
						for _, a := range quakeAssets {
							assets = append(assets, m.convertQuakeAsset(a))
						}
					}
				}
			}

			mu.Lock()
			allAssets = append(allAssets, assets...)
			mu.Unlock()

		}(source)
	}

	wg.Wait()
	return allAssets
}

// convertFofaAsset 转换 Fofa 资产为统一格式
func (m *APIManager) convertFofaAsset(a FofaAsset) UnifiedAsset {
	port := 0
	if a.Port != "" {
		fmt.Sscanf(a.Port, "%d", &port)
	}
	return UnifiedAsset{
		Host:       a.Host,
		IP:         a.IP,
		Port:       port,
		Protocol:   a.Protocol,
		Domain:     a.Domain,
		Title:      a.Title,
		Server:     a.Server,
		Country:    a.Country,
		City:       a.City,
		Banner:     a.Banner,
		Cert:       a.Cert,
		Source:     "fofa",
		UpdateTime: a.UpdateTime,
	}
}

// convertHunterAsset 转换 Hunter 资产为统一格式
func (m *APIManager) convertHunterAsset(a HunterAsset) UnifiedAsset {
	var components []string
	for _, c := range a.Component {
		if c.Version != "" {
			components = append(components, c.Name+"/"+c.Version)
		} else {
			components = append(components, c.Name)
		}
	}
	return UnifiedAsset{
		Host:       a.URL,
		IP:         a.IP,
		Port:       a.Port,
		Protocol:   a.Protocol,
		Domain:     a.Domain,
		Title:      a.WebTitle,
		Country:    a.Country,
		City:       a.City,
		ISP:        a.ISP,
		Banner:     a.Banner,
		Components: components,
		Source:     "hunter",
		UpdateTime: a.UpdateTime,
	}
}

// convertQuakeAsset 转换 Quake 资产为统一格式
func (m *APIManager) convertQuakeAsset(a QuakeAsset) UnifiedAsset {
	return UnifiedAsset{
		Host:       a.Hostname,
		IP:         a.IP,
		Port:       a.Port,
		Protocol:   a.Transport,
		Domain:     a.Domain,
		Title:      a.Service.HTTP.Title,
		Server:     a.Service.HTTP.Server,
		Country:    a.Location.Country,
		City:       a.Location.City,
		ISP:        a.Location.ISP,
		Banner:     a.Service.Response,
		Cert:       a.Service.Cert,
		Components: a.Components,
		Source:     "quake",
		UpdateTime: a.Time,
	}
}

// extractDomainFromHost 从 host 中提取域名
func extractDomainFromHost(host string) string {
	// 移除协议
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	// 移除端口
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}
	// 移除路径
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}
	return host
}
