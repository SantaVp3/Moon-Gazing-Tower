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

// RadScanner 使用 rad 进行浏览器爬虫（基于 Chrome）
type RadScanner struct {
	BinPath          string
	Timeout          int    // 超时时间(秒)
	MaxDepth         int    // 最大深度
	Concurrency      int    // 并发数
	TempDir          string
	ExecutionTimeout int    // 执行超时时间（分钟）
}

// RadResult rad 爬虫结果
type RadResult struct {
	Target    string       `json:"target"`
	URLs      []RadURL     `json:"urls"`
	StartTime time.Time    `json:"start_time"`
	EndTime   time.Time    `json:"end_time"`
	Duration  string       `json:"duration"`
	Total     int          `json:"total"`
}

// RadURL rad 发现的 URL
type RadURL struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Source     string `json:"source,omitempty"`
	ParentURL  string `json:"parent_url,omitempty"`
}

// RadJSONOutput rad JSON 输出格式
type RadJSONOutput struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	Source    string `json:"source"`
	ParentURL string `json:"parent_url"`
}

// NewRadScanner 创建 rad 扫描器
func NewRadScanner() *RadScanner {
	tm := core.NewToolsManager()
	binPath := tm.GetToolPath("rad")

	return &RadScanner{
		BinPath:          binPath,
		Timeout:          120,
		MaxDepth:         3,
		Concurrency:      5,
		TempDir:          os.TempDir(),
		ExecutionTimeout: 30, // 默认 30 分钟超时
	}
}

// IsAvailable 检查是否可用
func (r *RadScanner) IsAvailable() bool {
	return r.BinPath != "" && core.FileExists(r.BinPath)
}

// Crawl 使用浏览器爬取目标
func (r *RadScanner) Crawl(ctx context.Context, target string) (*RadResult, error) {
	if !r.IsAvailable() {
		return nil, fmt.Errorf("rad not available")
	}

	result := &RadResult{
		Target:    target,
		StartTime: time.Now(),
		URLs:      make([]RadURL, 0),
	}

	// 确保目标有协议
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// 创建临时输出文件
	outputFile, err := os.CreateTemp(r.TempDir, "rad_output_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	outputPath := outputFile.Name()
	outputFile.Close()
	defer os.Remove(outputPath)

	// 构建命令
	// rad -t target -o output --timeout timeout
	args := []string{
		"-t", target,
		"-o", outputPath,
	}

	cmd := exec.CommandContext(ctx, r.BinPath, args...)

	// 设置环境变量以无头模式运行
	cmd.Env = append(os.Environ(), "DISPLAY=")

	fmt.Printf("[*] Running rad: %s %s\n", r.BinPath, strings.Join(args, " "))

	// 使用 CombinedOutput 捕获所有输出
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		fmt.Printf("[!] rad error: %v, output: %s\n", err, string(output))
	}

	// 解析输出文件
	file, err := os.Open(outputPath)
	if err != nil {
		// 如果没有输出文件，尝试从 stdout 解析
		return r.parseOutput(string(output), result), nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 尝试解析 JSON
		var jsonOutput RadJSONOutput
		if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
			if jsonOutput.URL != "" && !seen[jsonOutput.URL] {
				seen[jsonOutput.URL] = true
				result.URLs = append(result.URLs, RadURL{
					URL:       jsonOutput.URL,
					Method:    jsonOutput.Method,
					Source:    jsonOutput.Source,
					ParentURL: jsonOutput.ParentURL,
				})
			}
		} else {
			// 纯文本，每行一个 URL
			if strings.HasPrefix(line, "http") && !seen[line] {
				seen[line] = true
				result.URLs = append(result.URLs, RadURL{
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

// parseOutput 从输出文本解析 URL
func (r *RadScanner) parseOutput(output string, result *RadResult) *RadResult {
	seen := make(map[string]bool)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 尝试解析 JSON
		var jsonOutput RadJSONOutput
		if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
			if jsonOutput.URL != "" && !seen[jsonOutput.URL] {
				seen[jsonOutput.URL] = true
				result.URLs = append(result.URLs, RadURL{
					URL:       jsonOutput.URL,
					Method:    jsonOutput.Method,
					Source:    jsonOutput.Source,
					ParentURL: jsonOutput.ParentURL,
				})
			}
		} else if strings.HasPrefix(line, "http") && !seen[line] {
			seen[line] = true
			result.URLs = append(result.URLs, RadURL{
				URL: line,
			})
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	result.Total = len(result.URLs)

	return result
}

// QuickCrawl 快速爬取
func (r *RadScanner) QuickCrawl(ctx context.Context, target string) (*RadResult, error) {
	r.Timeout = 60
	return r.Crawl(ctx, target)
}
