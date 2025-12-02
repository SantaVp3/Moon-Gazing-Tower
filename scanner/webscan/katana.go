package webscan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"moongazing/scanner/core"
	"os"
	"os/exec"
	"strings"
	"time"
)

// KatanaScanner 使用 Katana 进行网页爬虫
type KatanaScanner struct {
	BinPath          string
	Depth            int    // 爬取深度
	Concurrency      int    // 并发数
	Timeout          int    // 超时时间(秒)
	RateLimit        int    // 每秒请求数
	TempDir          string
	ExecutionTimeout int    // 执行超时时间（分钟）
}

// KatanaResult Katana 爬虫结果
type KatanaResult struct {
	Target    string              `json:"target"`
	URLs      []KatanaCrawledURL  `json:"urls"`
	StartTime time.Time           `json:"start_time"`
	EndTime   time.Time           `json:"end_time"`
	Duration  string              `json:"duration"`
	Total     int                 `json:"total"`
}

// KatanaCrawledURL 爬取到的URL
type KatanaCrawledURL struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Source     string `json:"source,omitempty"` // 来源：form, script, link, etc.
}

// KatanaJSONOutput Katana JSON 输出格式
type KatanaJSONOutput struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		Method   string `json:"method"`
		Endpoint string `json:"endpoint"`
		Raw      string `json:"raw"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
}

// NewKatanaScanner 创建 Katana 扫描器
func NewKatanaScanner() *KatanaScanner {
	tm := core.NewToolsManager()
	binPath := tm.GetToolPath("katana")

	return &KatanaScanner{
		BinPath:          binPath,
		Depth:            5,
		Concurrency:      5,
		Timeout:          5,
		RateLimit:        150,
		TempDir:          os.TempDir(),
		ExecutionTimeout: 20,
	}
}

// IsAvailable 检查是否可用
func (k *KatanaScanner) IsAvailable() bool {
	return k.BinPath != "" && core.FileExists(k.BinPath)
}

// Crawl 爬取目标网站
func (k *KatanaScanner) Crawl(ctx context.Context, target string) (*KatanaResult, error) {
	if !k.IsAvailable() {
		return nil, fmt.Errorf("katana not available")
	}

	result := &KatanaResult{
		Target:    target,
		StartTime: time.Now(),
		URLs:      make([]KatanaCrawledURL, 0),
	}

	// 确保目标有协议
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 创建临时输出文件
	outputFile, err := os.CreateTemp(k.TempDir, "katana_output_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// 构建命令
	// katana -u target -d depth -c concurrency -timeout timeout -rl rate -jsonl -o output
	args := []string{
		"-u", target,
		"-d", fmt.Sprintf("%d", k.Depth),
		"-c", fmt.Sprintf("%d", k.Concurrency),
		"-timeout", fmt.Sprintf("%d", k.Timeout),
		"-rl", fmt.Sprintf("%d", k.RateLimit),
		"-silent",
		"-jsonl", // 使用 JSON Lines 格式输出，包含状态码等信息
		"-o", outputPath,
	}

	cmd := exec.CommandContext(ctx, k.BinPath, args...)

	fmt.Printf("[*] Running Katana: %s %s\n", k.BinPath, strings.Join(args, " "))

	err = cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] Katana error: %v\n", err)
	}

	// 解析输出
	file, err := os.Open(outputPath)
	if err != nil {
		return result, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 尝试解析 JSON 格式
		var jsonOutput KatanaJSONOutput
		if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
			url := jsonOutput.Request.Endpoint
			if url != "" && !seen[url] {
				seen[url] = true
				result.URLs = append(result.URLs, KatanaCrawledURL{
					URL:        url,
					Method:     jsonOutput.Request.Method,
					StatusCode: jsonOutput.Response.StatusCode,
				})
			}
		} else {
			// 纯文本格式（每行一个URL）
			if !seen[line] {
				seen[line] = true
				result.URLs = append(result.URLs, KatanaCrawledURL{
					URL: line,
				})
			}
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.Total = len(result.URLs)

	return result, nil
}

// QuickCrawl 快速爬取（深度2）
func (k *KatanaScanner) QuickCrawl(ctx context.Context, target string) (*KatanaResult, error) {
	k.Depth = 2
	return k.Crawl(ctx, target)
}

// DeepCrawl 深度爬取（深度5）
func (k *KatanaScanner) DeepCrawl(ctx context.Context, target string) (*KatanaResult, error) {
	k.Depth = 5
	return k.Crawl(ctx, target)
}
