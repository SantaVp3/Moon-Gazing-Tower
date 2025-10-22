package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
)

// PoCExecutor PoC执行器
type PoCExecutor struct {
	client        *http.Client
	neutronEngine *NeutronEngine
}

// NewPoCExecutor 创建PoC执行器
func NewPoCExecutor() *PoCExecutor {
	return &PoCExecutor{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		neutronEngine: NewNeutronEngine(),
	}
}

// NucleiTemplate Nuclei模板结构（简化版）
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Reference   []string `yaml:"reference"`
		Tags        []string `yaml:"tags"`
	} `yaml:"info"`
	Requests []struct {
		Method  string            `yaml:"method"`
		Path    []string          `yaml:"path"`
		Headers map[string]string `yaml:"headers"`
		Body    string            `yaml:"body"`
		Matchers []struct {
			Type   string   `yaml:"type"`
			Words  []string `yaml:"words"`
			Regex  []string `yaml:"regex"`
			Status []int    `yaml:"status"`
			Part   string   `yaml:"part"`
		} `yaml:"matchers"`
		MatchersCondition string `yaml:"matchers-condition"` // and/or
	} `yaml:"requests"`
}

// ExecuteResult 执行结果
type ExecuteResult struct {
	Vulnerable bool
	Message    string
	Details    string
}

// Execute 执行PoC
func (e *PoCExecutor) Execute(poc *models.PoC, target string) (*ExecuteResult, error) {
	// 确保target以http或https开头
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	switch poc.PoCType {
	case "nuclei":
		// 使用Neutron引擎执行Nuclei格式的PoC
		return e.executeNucleiPoCWithNeutron(poc, target)
	case "custom":
		return e.executeCustomPoC(poc, target)
	default:
		return nil, fmt.Errorf("unsupported PoC type: %s", poc.PoCType)
	}
}

// executeNucleiPoCWithNeutron 使用Neutron引擎执行Nuclei格式的PoC
func (e *PoCExecutor) executeNucleiPoCWithNeutron(poc *models.PoC, target string) (*ExecuteResult, error) {
	result, err := e.neutronEngine.ExecutePoC(poc, target)
	if err != nil {
		return nil, fmt.Errorf("neutron execution failed: %w", err)
	}

	return &ExecuteResult{
		Vulnerable: result.Vulnerable,
		Message:    result.Message,
		Details:    fmt.Sprintf("Template: %s, Matcher: %s", result.TemplateID, result.MatcherName),
	}, nil
}

// executeNucleiPoC 执行Nuclei格式的PoC (保留原方法作为fallback)
func (e *PoCExecutor) executeNucleiPoC(poc *models.PoC, target string) (*ExecuteResult, error) {
	var template NucleiTemplate
	if err := yaml.Unmarshal([]byte(poc.PoCContent), &template); err != nil {
		return nil, fmt.Errorf("failed to parse nuclei template: %v", err)
	}

	// 遍历所有请求
	for _, request := range template.Requests {
		// 默认方法为GET
		method := request.Method
		if method == "" {
			method = "GET"
		}

		// 遍历所有路径
		for _, path := range request.Path {
			// 构建完整URL
			url := target
			if !strings.HasSuffix(target, "/") && !strings.HasPrefix(path, "/") {
				url += "/"
			}
			url += strings.TrimPrefix(path, "/")

			// 创建HTTP请求
			req, err := http.NewRequest(method, url, strings.NewReader(request.Body))
			if err != nil {
				continue
			}

			// 设置请求头
			for key, value := range request.Headers {
				req.Header.Set(key, value)
			}

			// 设置默认User-Agent
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			}

			// 发送请求
			resp, err := e.client.Do(req)
			if err != nil {
				continue
			}

			// 读取响应
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// 检查匹配器
			matched := e.checkMatchers(request.Matchers, request.MatchersCondition, resp, body)
			if matched {
				return &ExecuteResult{
					Vulnerable: true,
					Message:    fmt.Sprintf("Vulnerability detected: %s", template.Info.Name),
					Details:    fmt.Sprintf("URL: %s\nStatus: %d\nSeverity: %s", url, resp.StatusCode, template.Info.Severity),
				}, nil
			}
		}
	}

	return &ExecuteResult{
		Vulnerable: false,
		Message:    "No vulnerability detected",
		Details:    "Target is safe",
	}, nil
}

// checkMatchers 检查匹配器
func (e *PoCExecutor) checkMatchers(matchers []struct {
	Type   string   `yaml:"type"`
	Words  []string `yaml:"words"`
	Regex  []string `yaml:"regex"`
	Status []int    `yaml:"status"`
	Part   string   `yaml:"part"`
}, condition string, resp *http.Response, body []byte) bool {
	if len(matchers) == 0 {
		return false
	}

	// 默认条件为or
	if condition == "" {
		condition = "or"
	}

	results := make([]bool, len(matchers))

	for i, matcher := range matchers {
		results[i] = e.checkSingleMatcher(matcher, resp, body)
	}

	// 根据条件组合结果
	if condition == "and" {
		for _, result := range results {
			if !result {
				return false
			}
		}
		return true
	} else { // or
		for _, result := range results {
			if result {
				return true
			}
		}
		return false
	}
}

// checkSingleMatcher 检查单个匹配器
func (e *PoCExecutor) checkSingleMatcher(matcher struct {
	Type   string   `yaml:"type"`
	Words  []string `yaml:"words"`
	Regex  []string `yaml:"regex"`
	Status []int    `yaml:"status"`
	Part   string   `yaml:"part"`
}, resp *http.Response, body []byte) bool {
	bodyStr := string(body)

	// 获取检查部分（默认为body）
	checkContent := bodyStr
	if matcher.Part == "header" {
		checkContent = fmt.Sprintf("%v", resp.Header)
	}

	switch matcher.Type {
	case "word", "words":
		// 检查关键词（所有关键词都必须存在）
		for _, word := range matcher.Words {
			if !strings.Contains(checkContent, word) {
				return false
			}
		}
		return len(matcher.Words) > 0

	case "regex":
		// 检查正则表达式
		for _, pattern := range matcher.Regex {
			matched, err := regexp.MatchString(pattern, checkContent)
			if err != nil || !matched {
				return false
			}
		}
		return len(matcher.Regex) > 0

	case "status":
		// 检查状态码
		for _, status := range matcher.Status {
			if resp.StatusCode == status {
				return true
			}
		}
		return false

	case "dsl":
		// DSL表达式支持（简化版：只支持状态码和长度检查）
		// 例如: "status_code == 200 && len(body) > 100"
		// 这里简化处理，只检查状态码
		return resp.StatusCode == 200

	default:
		return false
	}
}

// executeCustomPoC 执行自定义PoC
func (e *PoCExecutor) executeCustomPoC(poc *models.PoC, target string) (*ExecuteResult, error) {
	// 自定义PoC执行逻辑（预留扩展）
	return &ExecuteResult{
		Vulnerable: false,
		Message:    "Custom PoC execution not implemented yet",
		Details:    "",
	}, nil
}

// BatchExecute 批量执行PoC
func (e *PoCExecutor) BatchExecute(pocs []*models.PoC, target string) []*ExecuteResult {
	results := make([]*ExecuteResult, 0, len(pocs))

	for _, poc := range pocs {
		if !poc.IsEnabled {
			continue
		}

		result, err := e.Execute(poc, target)
		if err != nil {
			results = append(results, &ExecuteResult{
				Vulnerable: false,
				Message:    fmt.Sprintf("Execution error: %v", err),
				Details:    "",
			})
			continue
		}

		results = append(results, result)
	}

	return results
}
