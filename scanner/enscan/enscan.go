package enscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"moongazing/scanner/core"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ENScanScanner 企业信息扫描器（基于 ENScan_GO）
// 支持查询 APP、小程序、微信公众号、ICP备案等信息
type ENScanScanner struct {
	execPath    string
	configPath  string
	apiURL      string
	httpClient  *http.Client
	apiMode     bool
	apiProcess  *exec.Cmd
	mu          sync.Mutex
	concurrency int
}

// ENScanConfig ENScan 配置
type ENScanConfig struct {
	Cookies struct {
		Aiqicha     string `yaml:"aiqicha"`
		Tianyancha  string `yaml:"tianyancha"`
		Tycid       string `yaml:"tycid"`
		AuthToken   string `yaml:"auth_token"`
		TycAPIToken string `yaml:"tyc_api_token"`
		RiskBird    string `yaml:"risk_bird"`
		Qimai       string `yaml:"qimai"`
	} `yaml:"cookies"`
}

// ENScanResult ENScan 查询结果
type ENScanResult struct {
	Company     string             `json:"company"`      // 公司名称
	PID         string             `json:"pid"`          // 公司PID
	Apps        []AppInfo          `json:"apps"`         // APP信息
	WxApps      []WxAppInfo        `json:"wx_apps"`      // 微信小程序
	Wechats     []WechatInfo       `json:"wechats"`      // 微信公众号
	ICPs        []ICPInfo          `json:"icps"`         // ICP备案
	Weibos      []WeiboInfo        `json:"weibos"`       // 微博
	Copyrights  []CopyrightInfo    `json:"copyrights"`   // 软件著作权
	Jobs        []JobInfo          `json:"jobs"`         // 招聘信息
	Investments []InvestmentInfo   `json:"investments"`  // 对外投资
	Branches    []BranchInfo       `json:"branches"`     // 分支机构
	Source      string             `json:"source"`       // 数据来源
	QueryTime   time.Time          `json:"query_time"`   // 查询时间
}

// AppInfo APP信息
type AppInfo struct {
	Name        string `json:"name"`         // APP名称
	Category    string `json:"category"`     // 分类
	Logo        string `json:"logo"`         // 图标URL
	Description string `json:"description"`  // 描述
	Version     string `json:"version"`      // 版本
	UpdateTime  string `json:"update_time"`  // 更新时间
	DownloadURL string `json:"download_url"` // 下载链接
	Market      string `json:"market"`       // 应用市场
	Package     string `json:"package"`      // 包名
	Developer   string `json:"developer"`    // 开发者
}

// WxAppInfo 微信小程序信息
type WxAppInfo struct {
	Name        string `json:"name"`        // 小程序名称
	AppID       string `json:"app_id"`      // 小程序AppID
	Logo        string `json:"logo"`        // 图标
	Description string `json:"description"` // 描述
	Category    string `json:"category"`    // 分类
	QRCode      string `json:"qr_code"`     // 二维码
}

// WechatInfo 微信公众号信息
type WechatInfo struct {
	Name        string `json:"name"`         // 公众号名称
	WechatID    string `json:"wechat_id"`    // 微信号
	Logo        string `json:"logo"`         // 头像
	Description string `json:"description"`  // 简介
	QRCode      string `json:"qr_code"`      // 二维码
	Verified    bool   `json:"verified"`     // 是否认证
}

// ICPInfo ICP备案信息
type ICPInfo struct {
	Domain      string `json:"domain"`       // 域名
	ICP         string `json:"icp"`          // 备案号
	SiteName    string `json:"site_name"`    // 网站名称
	CompanyName string `json:"company_name"` // 公司名称
	CompanyType string `json:"company_type"` // 单位性质
	UpdateTime  string `json:"update_time"`  // 更新时间
}

// WeiboInfo 微博信息
type WeiboInfo struct {
	Name        string `json:"name"`        // 微博名称
	WeiboID     string `json:"weibo_id"`    // 微博ID
	URL         string `json:"url"`         // 微博链接
	Verified    bool   `json:"verified"`    // 是否认证
	Description string `json:"description"` // 简介
	Followers   int    `json:"followers"`   // 粉丝数
}

// CopyrightInfo 软件著作权信息
type CopyrightInfo struct {
	Name          string `json:"name"`           // 软件名称
	ShortName     string `json:"short_name"`     // 简称
	Version       string `json:"version"`        // 版本号
	RegisterNo    string `json:"register_no"`    // 登记号
	Category      string `json:"category"`       // 分类
	RegisterDate  string `json:"register_date"`  // 登记日期
	PublishDate   string `json:"publish_date"`   // 首次发表日期
}

// JobInfo 招聘信息
type JobInfo struct {
	Title      string `json:"title"`       // 职位名称
	Location   string `json:"location"`    // 工作地点
	Salary     string `json:"salary"`      // 薪资
	Experience string `json:"experience"`  // 经验要求
	Education  string `json:"education"`   // 学历要求
	Source     string `json:"source"`      // 来源平台
	URL        string `json:"url"`         // 链接
}

// InvestmentInfo 对外投资信息
type InvestmentInfo struct {
	CompanyName string  `json:"company_name"` // 被投资公司
	Ratio       float64 `json:"ratio"`        // 持股比例
	Amount      string  `json:"amount"`       // 投资金额
	Status      string  `json:"status"`       // 状态
}

// BranchInfo 分支机构信息
type BranchInfo struct {
	Name   string `json:"name"`   // 分支名称
	Status string `json:"status"` // 状态
}

// NewENScanScanner 创建企业信息扫描器
func NewENScanScanner() *ENScanScanner {
	scanner := &ENScanScanner{
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		apiURL:      "http://127.0.0.1:31000",
		concurrency: 5,
	}
	
	// 使用 ToolsManager 查找工具
	tm := core.NewToolsManager()
	scanner.execPath = tm.GetToolPath("enscan")
	if scanner.execPath != "" {
		scanner.configPath = filepath.Join(filepath.Dir(scanner.execPath), "config.yaml")
		log.Printf("[ENScan] Found executable at: %s", scanner.execPath)
	}
	
	return scanner
}

// findExecutable 查找可执行文件
func (s *ENScanScanner) findExecutable() {
	// 兼容旧代码，实际已在 NewENScanScanner 中处理
	if s.execPath != "" {
		return
	}
	
	tm := core.NewToolsManager()
	s.execPath = tm.GetToolPath("enscan")
	if s.execPath != "" {
		s.configPath = filepath.Join(filepath.Dir(s.execPath), "config.yaml")
	}
}

// IsAvailable 检查是否可用
func (s *ENScanScanner) IsAvailable() bool {
	return s.execPath != ""
}

// CheckConfig 检查配置文件状态
// 返回配置的数据源列表和是否已配置
func (s *ENScanScanner) CheckConfig() (configuredSources []string, err error) {
	if s.configPath == "" {
		return nil, fmt.Errorf("config path not found")
	}

	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config struct {
		Cookies struct {
			Aiqicha     string `yaml:"aiqicha"`
			Tianyancha  string `yaml:"tianyancha"`
			Tycid       string `yaml:"tycid"`
			AuthToken   string `yaml:"auth_token"`
			TycAPIToken string `yaml:"tyc_api_token"`
			RiskBird    string `yaml:"risk_bird"`
			Qimai       string `yaml:"qimai"`
		} `yaml:"cookies"`
		App struct {
			MiitAPI string `yaml:"miit_api"`
		} `yaml:"app"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// 检查各数据源的 cookie 配置
	if config.Cookies.Aiqicha != "" {
		configuredSources = append(configuredSources, "aiqicha")
	}
	if config.Cookies.Tianyancha != "" {
		configuredSources = append(configuredSources, "tianyancha")
	}
	if config.Cookies.Tycid != "" && config.Cookies.AuthToken != "" {
		configuredSources = append(configuredSources, "tianyancha_api")
	}
	if config.Cookies.TycAPIToken != "" {
		configuredSources = append(configuredSources, "tianyancha_official_api")
	}
	if config.Cookies.RiskBird != "" {
		configuredSources = append(configuredSources, "riskbird")
	}
	if config.Cookies.Qimai != "" {
		configuredSources = append(configuredSources, "qimai")
	}
	if config.App.MiitAPI != "" {
		configuredSources = append(configuredSources, "miit_icp")
	}

	return configuredSources, nil
}

// GetConfigPath 获取配置文件路径
func (s *ENScanScanner) GetConfigPath() string {
	return s.configPath
}

// StartAPIServer 启动 API 服务器
func (s *ENScanScanner) StartAPIServer(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.apiProcess != nil {
		return nil // 已经启动
	}

	if !s.IsAvailable() {
		return fmt.Errorf("enscan executable not found")
	}

	// 启动 API 服务
	cmd := exec.CommandContext(ctx, s.execPath, "--api")
	cmd.Dir = filepath.Dir(s.execPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start enscan api: %w", err)
	}

	s.apiProcess = cmd
	s.apiMode = true

	// 等待 API 服务启动
	time.Sleep(3 * time.Second)

	// 检查服务是否启动成功
	for i := 0; i < 10; i++ {
		resp, err := s.httpClient.Get(s.apiURL + "/api/info?name=test")
		if err == nil {
			resp.Body.Close()
			log.Printf("[ENScan] API server started successfully")
			return nil
		}
		time.Sleep(time.Second)
	}

	return fmt.Errorf("enscan api server failed to start")
}

// StopAPIServer 停止 API 服务器
func (s *ENScanScanner) StopAPIServer() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.apiProcess != nil {
		s.apiProcess.Process.Kill()
		s.apiProcess = nil
		s.apiMode = false
	}
}

// QueryCompany 查询公司信息
func (s *ENScanScanner) QueryCompany(ctx context.Context, companyName string, opts *ENScanQueryOptions) (*ENScanResult, error) {
	if opts == nil {
		opts = &ENScanQueryOptions{
			Fields: []string{"app", "wx_app", "wechat", "icp"},
			Source: "aqc",
		}
	}

	// 优先使用 API 模式
	if s.apiMode {
		return s.queryViaAPI(ctx, companyName, opts)
	}

	// 否则使用命令行模式
	return s.queryViaCLI(ctx, companyName, opts)
}

// ENScanQueryOptions 查询选项
type ENScanQueryOptions struct {
	Fields      []string // 查询字段: app, wx_app, wechat, icp, weibo, copyright, job
	Source      string   // 数据源: aqc, tyc, all
	InvestRatio int      // 投资比例筛选
	Depth       int      // 递归深度
	Branch      bool     // 是否查询分支机构
	Delay       int      // 请求延迟（秒）
}

// queryViaAPI 通过 API 查询
func (s *ENScanScanner) queryViaAPI(ctx context.Context, companyName string, opts *ENScanQueryOptions) (*ENScanResult, error) {
	// 构建请求 URL
	params := url.Values{}
	params.Set("name", companyName)
	
	if opts.Source != "" {
		params.Set("type", opts.Source)
	}
	if len(opts.Fields) > 0 {
		params.Set("field", strings.Join(opts.Fields, ","))
	}
	if opts.InvestRatio > 0 {
		params.Set("invest", fmt.Sprintf("%d", opts.InvestRatio))
	}
	if opts.Depth > 0 {
		params.Set("depth", fmt.Sprintf("%d", opts.Depth))
	}
	if opts.Branch {
		params.Set("branch", "true")
	}

	reqURL := fmt.Sprintf("%s/api/info?%s", s.apiURL, params.Encode())
	
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 解析响应
	return s.parseAPIResponse(companyName, body, opts.Source)
}

// queryViaCLI 通过命令行查询
func (s *ENScanScanner) queryViaCLI(ctx context.Context, companyName string, opts *ENScanQueryOptions) (*ENScanResult, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("enscan executable not found")
	}

	// 构建命令参数
	args := []string{"-n", companyName, "-is-show"}
	
	if opts.Source != "" {
		args = append(args, "-type", opts.Source)
	}
	if len(opts.Fields) > 0 {
		args = append(args, "-field", strings.Join(opts.Fields, ","))
	}
	if opts.InvestRatio > 0 {
		args = append(args, "-invest", fmt.Sprintf("%d", opts.InvestRatio))
	}
	if opts.Depth > 0 {
		args = append(args, "-deep", fmt.Sprintf("%d", opts.Depth))
	}
	if opts.Branch {
		args = append(args, "--branch")
	}
	if opts.Delay > 0 {
		args = append(args, "-delay", fmt.Sprintf("%d", opts.Delay))
	}

	cmd := exec.CommandContext(ctx, s.execPath, args...)
	cmd.Dir = filepath.Dir(s.execPath)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("enscan command failed: %w", err)
	}

	// 解析命令输出
	return s.parseCLIOutput(companyName, output, opts.Source)
}

// parseAPIResponse 解析 API 响应
func (s *ENScanScanner) parseAPIResponse(companyName string, body []byte, source string) (*ENScanResult, error) {
	result := &ENScanResult{
		Company:   companyName,
		Source:    source,
		QueryTime: time.Now(),
		Apps:      make([]AppInfo, 0),
		WxApps:    make([]WxAppInfo, 0),
		Wechats:   make([]WechatInfo, 0),
		ICPs:      make([]ICPInfo, 0),
	}

	// ENScan API 返回格式
	var apiResp map[string]interface{}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return result, nil // 返回空结果而不是错误
	}

	// 解析数据
	if data, ok := apiResp["data"].(map[string]interface{}); ok {
		// 解析 APP 信息
		if apps, ok := data["app"].([]interface{}); ok {
			for _, app := range apps {
				if appMap, ok := app.(map[string]interface{}); ok {
					result.Apps = append(result.Apps, AppInfo{
						Name:        getString(appMap, "name"),
						Category:    getString(appMap, "category"),
						Logo:        getString(appMap, "logo"),
						Description: getString(appMap, "description"),
						Version:     getString(appMap, "version"),
						Package:     getString(appMap, "package"),
						Developer:   getString(appMap, "developer"),
					})
				}
			}
		}

		// 解析微信小程序
		if wxApps, ok := data["wx_app"].([]interface{}); ok {
			for _, wxApp := range wxApps {
				if wxAppMap, ok := wxApp.(map[string]interface{}); ok {
					result.WxApps = append(result.WxApps, WxAppInfo{
						Name:        getString(wxAppMap, "name"),
						AppID:       getString(wxAppMap, "app_id"),
						Logo:        getString(wxAppMap, "logo"),
						Description: getString(wxAppMap, "description"),
						Category:    getString(wxAppMap, "category"),
					})
				}
			}
		}

		// 解析微信公众号
		if wechats, ok := data["wechat"].([]interface{}); ok {
			for _, wechat := range wechats {
				if wechatMap, ok := wechat.(map[string]interface{}); ok {
					result.Wechats = append(result.Wechats, WechatInfo{
						Name:        getString(wechatMap, "name"),
						WechatID:    getString(wechatMap, "wechat_id"),
						Logo:        getString(wechatMap, "logo"),
						Description: getString(wechatMap, "description"),
					})
				}
			}
		}

		// 解析 ICP 备案
		if icps, ok := data["icp"].([]interface{}); ok {
			for _, icp := range icps {
				if icpMap, ok := icp.(map[string]interface{}); ok {
					result.ICPs = append(result.ICPs, ICPInfo{
						Domain:      getString(icpMap, "domain"),
						ICP:         getString(icpMap, "icp"),
						SiteName:    getString(icpMap, "site_name"),
						CompanyName: getString(icpMap, "company_name"),
					})
				}
			}
		}
	}

	return result, nil
}

// parseCLIOutput 解析命令行输出
func (s *ENScanScanner) parseCLIOutput(companyName string, output []byte, source string) (*ENScanResult, error) {
	result := &ENScanResult{
		Company:   companyName,
		Source:    source,
		QueryTime: time.Now(),
		Apps:      make([]AppInfo, 0),
		WxApps:    make([]WxAppInfo, 0),
		Wechats:   make([]WechatInfo, 0),
		ICPs:      make([]ICPInfo, 0),
	}

	// ENScan CLI 输出的解析逻辑
	// 由于 CLI 输出格式可能不是 JSON，这里做基本解析
	lines := strings.Split(string(output), "\n")
	
	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 识别段落
		if strings.Contains(line, "APP") || strings.Contains(line, "应用") {
			currentSection = "app"
			continue
		}
		if strings.Contains(line, "小程序") {
			currentSection = "wx_app"
			continue
		}
		if strings.Contains(line, "公众号") {
			currentSection = "wechat"
			continue
		}
		if strings.Contains(line, "ICP") || strings.Contains(line, "备案") {
			currentSection = "icp"
			continue
		}

		// 根据段落解析数据
		switch currentSection {
		case "app":
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "=") {
				result.Apps = append(result.Apps, AppInfo{Name: line})
			}
		case "wx_app":
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "=") {
				result.WxApps = append(result.WxApps, WxAppInfo{Name: line})
			}
		case "wechat":
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "=") {
				result.Wechats = append(result.Wechats, WechatInfo{Name: line})
			}
		case "icp":
			if !strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "=") {
				result.ICPs = append(result.ICPs, ICPInfo{Domain: line})
			}
		}
	}

	return result, nil
}

// QueryApps 查询公司 APP 信息
func (s *ENScanScanner) QueryApps(ctx context.Context, companyName string) ([]AppInfo, error) {
	result, err := s.QueryCompany(ctx, companyName, &ENScanQueryOptions{
		Fields: []string{"app"},
		Source: "aqc",
	})
	if err != nil {
		return nil, err
	}
	return result.Apps, nil
}

// QueryWxApps 查询公司微信小程序
func (s *ENScanScanner) QueryWxApps(ctx context.Context, companyName string) ([]WxAppInfo, error) {
	result, err := s.QueryCompany(ctx, companyName, &ENScanQueryOptions{
		Fields: []string{"wx_app"},
		Source: "aqc",
	})
	if err != nil {
		return nil, err
	}
	return result.WxApps, nil
}

// QueryWechats 查询公司微信公众号
func (s *ENScanScanner) QueryWechats(ctx context.Context, companyName string) ([]WechatInfo, error) {
	result, err := s.QueryCompany(ctx, companyName, &ENScanQueryOptions{
		Fields: []string{"wechat"},
		Source: "aqc",
	})
	if err != nil {
		return nil, err
	}
	return result.Wechats, nil
}

// QueryICPs 查询公司 ICP 备案
func (s *ENScanScanner) QueryICPs(ctx context.Context, companyName string) ([]ICPInfo, error) {
	result, err := s.QueryCompany(ctx, companyName, &ENScanQueryOptions{
		Fields: []string{"icp"},
		Source: "aqc",
	})
	if err != nil {
		return nil, err
	}
	return result.ICPs, nil
}

// QueryAll 查询所有信息
func (s *ENScanScanner) QueryAll(ctx context.Context, companyName string) (*ENScanResult, error) {
	return s.QueryCompany(ctx, companyName, &ENScanQueryOptions{
		Fields: []string{"app", "wx_app", "wechat", "icp", "weibo", "copyright"},
		Source: "aqc",
	})
}

// BatchQuery 批量查询公司信息
func (s *ENScanScanner) BatchQuery(ctx context.Context, companies []string, opts *ENScanQueryOptions) ([]*ENScanResult, error) {
	results := make([]*ENScanResult, 0, len(companies))
	resultsMu := sync.Mutex{}

	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	for _, company := range companies {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := s.QueryCompany(ctx, name, opts)
			if err != nil {
				log.Printf("[ENScan] Query failed for %s: %v", name, err)
				return
			}

			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}(company)
	}

	wg.Wait()
	return results, nil
}

// getString 从 map 中安全获取字符串
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
