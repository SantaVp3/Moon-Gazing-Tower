package vulnscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"moongazing/scanner/core"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// NucleiCLIScanner 基于命令行的 Nuclei 扫描器
type NucleiCLIScanner struct {
	nucleiBinary    string
	templatesDir    string
	concurrency     int
	rateLimit       int
	timeout         time.Duration
	resultCallback  func(*NucleiResult)
	mu              sync.Mutex
}

// NucleiResult Nuclei 扫描结果
type NucleiResult struct {
	TemplateID       string    `json:"template-id"`
	TemplateName     string    `json:"info,omitempty"`
	Severity         string    `json:"severity"`
	Host             string    `json:"host"`
	URL              string    `json:"matched-at"`
	Matched          string    `json:"matched"`
	ExtractedResults []string  `json:"extracted-results,omitempty"`
	Request          string    `json:"request,omitempty"`
	Response         string    `json:"response,omitempty"`
	CVEID            string    `json:"cve-id,omitempty"`
	Description      string    `json:"description,omitempty"`
	Reference        []string  `json:"reference,omitempty"`
	Tags             string    `json:"tags,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
}

// NucleiJSONOutput Nuclei JSON 输出格式
type NucleiJSONOutput struct {
	TemplateID   string `json:"template-id"`
	TemplatePath string `json:"template-path"`
	Info         struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Severity    string   `json:"severity"`
		Classification struct {
			CVEID []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
	MatcherName      string   `json:"matcher-name"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Port             string   `json:"port"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	Timestamp        string   `json:"timestamp"`
}

// NucleiScanConfig 扫描配置
type NucleiScanConfig struct {
	Templates       []string      // 模板路径或 ID
	Tags            []string      // 标签过滤
	ExcludeTags     []string      // 排除标签
	Severity        string        // 严重程度过滤: critical,high,medium,low,info
	ExcludeSeverity string        // 排除严重程度
	Concurrency     int           // 并发数
	RateLimit       int           // 速率限制
	Timeout         time.Duration // 超时时间
}

// NewNucleiCLIScanner 创建 Nuclei CLI 扫描器
func NewNucleiCLIScanner(templatesDir string) *NucleiCLIScanner {
	scanner := &NucleiCLIScanner{
		templatesDir: templatesDir,
		concurrency:  25,
		rateLimit:    150,
		timeout:      5 * time.Minute,
	}

	// 自动检测 nuclei 二进制文件路径
	scanner.nucleiBinary = scanner.findNucleiBinary()

	return scanner
}

// findNucleiBinary 查找 nuclei 二进制文件
func (s *NucleiCLIScanner) findNucleiBinary() string {
	tm := core.NewToolsManager()
	path := tm.GetToolPath("nuclei")
	if path != "" {
		return path
	}
	
	// Fallback to PATH
	if path, err := exec.LookPath("nuclei"); err == nil {
		return path
	}
	
	return "nuclei"
}

// SetResultCallback 设置结果回调函数
func (s *NucleiCLIScanner) SetResultCallback(callback func(*NucleiResult)) {
	s.resultCallback = callback
}

// SetConcurrency 设置并发数
func (s *NucleiCLIScanner) SetConcurrency(c int) {
	if c > 0 {
		s.concurrency = c
	}
}

// SetRateLimit 设置速率限制
func (s *NucleiCLIScanner) SetRateLimit(r int) {
	if r > 0 {
		s.rateLimit = r
	}
}

// SetNucleiBinary 设置 nuclei 二进制文件路径
func (s *NucleiCLIScanner) SetNucleiBinary(path string) {
	s.nucleiBinary = path
}

// buildArgs 构建命令行参数
func (s *NucleiCLIScanner) buildArgs(targets []string, config *NucleiScanConfig) []string {
	args := []string{
		"-json",
		"-silent",
		"-no-color",
	}

	// 添加目标
	for _, target := range targets {
		args = append(args, "-u", target)
	}

	// 并发设置
	concurrency := s.concurrency
	if config != nil && config.Concurrency > 0 {
		concurrency = config.Concurrency
	}
	args = append(args, "-c", fmt.Sprintf("%d", concurrency))

	// 速率限制
	rateLimit := s.rateLimit
	if config != nil && config.RateLimit > 0 {
		rateLimit = config.RateLimit
	}
	args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))

	// 模板路径
	if config != nil && len(config.Templates) > 0 {
		for _, t := range config.Templates {
			args = append(args, "-t", t)
		}
	} else if s.templatesDir != "" {
		args = append(args, "-t", s.templatesDir)
	}

	// 标签过滤
	if config != nil {
		if len(config.Tags) > 0 {
			args = append(args, "-tags", strings.Join(config.Tags, ","))
		}
		if len(config.ExcludeTags) > 0 {
			args = append(args, "-etags", strings.Join(config.ExcludeTags, ","))
		}
		if config.Severity != "" {
			args = append(args, "-severity", config.Severity)
		}
		if config.ExcludeSeverity != "" {
			args = append(args, "-es", config.ExcludeSeverity)
		}
	}

	return args
}

// Scan 执行漏洞扫描
func (s *NucleiCLIScanner) Scan(ctx context.Context, targets []string, config *NucleiScanConfig) ([]*NucleiResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标列表为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	args := s.buildArgs(targets, config)

	// 设置超时
	timeout := s.timeout
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.nucleiBinary, args...)

	// 获取输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("创建输出管道失败: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 nuclei 失败: %w", err)
	}

	var results []*NucleiResult
	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		result, err := s.parseJSONLine(line)
		if err != nil {
			continue
		}

		results = append(results, result)

		// 调用回调
		if s.resultCallback != nil {
			s.resultCallback(result)
		}
	}

	// 等待命令完成
	if err := cmd.Wait(); err != nil {
		// 如果有结果，忽略退出错误（nuclei 可能返回非零状态码）
		if len(results) == 0 && ctx.Err() == nil {
			return nil, fmt.Errorf("nuclei 执行失败: %w", err)
		}
	}

	return results, nil
}

// parseJSONLine 解析 JSON 行
func (s *NucleiCLIScanner) parseJSONLine(line string) (*NucleiResult, error) {
	var output NucleiJSONOutput
	if err := json.Unmarshal([]byte(line), &output); err != nil {
		return nil, err
	}

	result := &NucleiResult{
		TemplateID:       output.TemplateID,
		TemplateName:     output.Info.Name,
		Severity:         output.Info.Severity,
		Host:             output.Host,
		URL:              output.MatchedAt,
		Description:      output.Info.Description,
		Reference:        output.Info.Reference,
		Tags:             strings.Join(output.Info.Tags, ","),
		ExtractedResults: output.ExtractedResults,
		Request:          output.Request,
		Response:         output.Response,
		Timestamp:        time.Now(),
	}

	// 提取 CVE ID
	if len(output.Info.Classification.CVEID) > 0 {
		result.CVEID = strings.Join(output.Info.Classification.CVEID, ",")
	}

	return result, nil
}

// ScanSingle 扫描单个目标
func (s *NucleiCLIScanner) ScanSingle(ctx context.Context, target string, config *NucleiScanConfig) ([]*NucleiResult, error) {
	return s.Scan(ctx, []string{target}, config)
}

// ScanWithTemplateID 使用指定模板扫描
func (s *NucleiCLIScanner) ScanWithTemplateID(ctx context.Context, targets []string, templateIDs []string) ([]*NucleiResult, error) {
	var templates []string
	for _, id := range templateIDs {
		// 如果是完整路径，直接使用
		if filepath.IsAbs(id) || strings.HasSuffix(id, ".yaml") {
			templates = append(templates, id)
		} else {
			// 否则在模板目录中查找
			templatePath := filepath.Join(s.templatesDir, id+".yaml")
			templates = append(templates, templatePath)
		}
	}

	config := &NucleiScanConfig{
		Templates: templates,
	}

	return s.Scan(ctx, targets, config)
}

// ScanBySeverity 按严重程度扫描
func (s *NucleiCLIScanner) ScanBySeverity(ctx context.Context, targets []string, severity string) ([]*NucleiResult, error) {
	config := &NucleiScanConfig{
		Severity: severity,
	}

	return s.Scan(ctx, targets, config)
}

// ScanByTags 按标签扫描
func (s *NucleiCLIScanner) ScanByTags(ctx context.Context, targets []string, tags []string) ([]*NucleiResult, error) {
	config := &NucleiScanConfig{
		Tags: tags,
	}

	return s.Scan(ctx, targets, config)
}

// VerifyVulnerability 验证漏洞（重新扫描确认）
func (s *NucleiCLIScanner) VerifyVulnerability(ctx context.Context, target string, templateID string) (*NucleiResult, error) {
	results, err := s.ScanWithTemplateID(ctx, []string{target}, []string{templateID})
	if err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return results[0], nil
	}

	return nil, nil // 未验证到漏洞
}

// IsAvailable 检查 nuclei 是否可用
func (s *NucleiCLIScanner) IsAvailable() bool {
	cmd := exec.Command(s.nucleiBinary, "-version")
	return cmd.Run() == nil
}

// GetVersion 获取 nuclei 版本
func (s *NucleiCLIScanner) GetVersion() string {
	cmd := exec.Command(s.nucleiBinary, "-version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// Close 关闭扫描器（CLI 版本不需要特殊清理）
func (s *NucleiCLIScanner) Close() {
	// CLI 版本不需要清理
}

// 全局实例
var GlobalNucleiScanner *NucleiCLIScanner

// InitGlobalNucleiScanner 初始化全局 Nuclei 扫描器
func InitGlobalNucleiScanner(templatesDir string) {
	GlobalNucleiScanner = NewNucleiCLIScanner(templatesDir)
}
