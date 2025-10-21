package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"

	"github.com/reconmaster/backend/internal/models"
)

// WebInfoHunter 扫描器
type WebInfoHunter struct {
	binPath string
}

// NewWebInfoHunter 创建WIH扫描器
func NewWebInfoHunter(binPath string) *WebInfoHunter {
	if binPath == "" {
		binPath = "webinfohunter" // 假设在PATH中
	}
	return &WebInfoHunter{
		binPath: binPath,
	}
}

// WIHResult WIH扫描结果
type WIHResult struct {
	URL              string   `json:"url"`
	Domains          []string `json:"domains"`
	Subdomains       []string `json:"subdomains"`
	AccessKeys       []string `json:"access_keys"`
	SecretKeys       []string `json:"secret_keys"`
	APIKeys          []string `json:"api_keys"`
	Tokens           []string `json:"tokens"`
	InternalIPs      []string `json:"internal_ips"`
	Emails           []string `json:"emails"`
	PhoneNumbers     []string `json:"phone_numbers"`
	APIEndpoints     []string `json:"api_endpoints"`
	SuspiciousStrings []string `json:"suspicious_strings"`
}

// Scan 执行WIH扫描
func (wih *WebInfoHunter) Scan(ctx *ScanContext, urls []string) ([]*WIHResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	ctx.Logger.Printf("Running WebInfoHunter on %d URLs", len(urls))

	var results []*WIHResult

	// 由于WIH可能不存在，我们使用爬虫提取JS信息作为替代
	crawler := NewCrawler()

	for _, targetURL := range urls {
		result := &WIHResult{
			URL:          targetURL,
			Domains:      []string{},
			Subdomains:   []string{},
			AccessKeys:   []string{},
			SecretKeys:   []string{},
			APIKeys:      []string{},
			Tokens:       []string{},
			InternalIPs:  []string{},
			Emails:       []string{},
			PhoneNumbers: []string{},
			APIEndpoints: []string{},
		}

		// 获取页面内容
		resp, err := crawler.client.Get(targetURL)
		if err != nil {
			ctx.Logger.Printf("Failed to fetch %s: %v", targetURL, err)
			continue
		}

		body, err := readResponseBody(resp)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// 提取JS文件
		jsFiles := crawler.ExtractJSFiles(string(body), targetURL)
		ctx.Logger.Printf("Found %d JS files in %s", len(jsFiles), targetURL)

		// 分析每个JS文件
		for _, jsURL := range jsFiles {
			jsResp, err := crawler.client.Get(jsURL)
			if err != nil {
				continue
			}

			jsBody, err := readResponseBody(jsResp)
			jsResp.Body.Close()
			if err != nil {
				continue
			}

			jsContent := string(jsBody)

			// 提取信息
			subdomains := crawler.ExtractSubdomains(jsContent)
			result.Subdomains = append(result.Subdomains, subdomains...)

			apis := crawler.ExtractAPIs(jsContent)
			result.APIEndpoints = append(result.APIEndpoints, apis...)

			sensitive := crawler.ExtractSensitiveInfo(jsContent)
			if keys, ok := sensitive["access_key"]; ok {
				result.AccessKeys = append(result.AccessKeys, keys...)
			}
			if keys, ok := sensitive["secret_key"]; ok {
				result.SecretKeys = append(result.SecretKeys, keys...)
			}
			if keys, ok := sensitive["api_key"]; ok {
				result.APIKeys = append(result.APIKeys, keys...)
			}
			if tokens, ok := sensitive["token"]; ok {
				result.Tokens = append(result.Tokens, tokens...)
			}
			if ips, ok := sensitive["internal_ip"]; ok {
				result.InternalIPs = append(result.InternalIPs, ips...)
			}

			// 提取邮箱
			emails := extractEmails(jsContent)
			result.Emails = append(result.Emails, emails...)
		}

		// 去重
		result.Subdomains = uniqueStrings(result.Subdomains)
		result.APIEndpoints = uniqueStrings(result.APIEndpoints)
		result.AccessKeys = uniqueStrings(result.AccessKeys)
		result.SecretKeys = uniqueStrings(result.SecretKeys)
		result.APIKeys = uniqueStrings(result.APIKeys)
		result.Tokens = uniqueStrings(result.Tokens)
		result.InternalIPs = uniqueStrings(result.InternalIPs)
		result.Emails = uniqueStrings(result.Emails)

		if len(result.Subdomains) > 0 || len(result.AccessKeys) > 0 || len(result.APIEndpoints) > 0 {
			results = append(results, result)
		}
	}

	return results, nil
}

// ScanWithBinary 使用二进制文件扫描
func (wih *WebInfoHunter) ScanWithBinary(urls []string) ([]*WIHResult, error) {
	if !checkWIHInstalled(wih.binPath) {
		return nil, fmt.Errorf("WebInfoHunter not installed")
	}

	var results []*WIHResult

	for _, url := range urls {
		cmd := exec.Command(wih.binPath, "-u", url, "-j")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			continue
		}

		if err := cmd.Start(); err != nil {
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			var result WIHResult
			if err := json.Unmarshal([]byte(line), &result); err == nil {
				results = append(results, &result)
			}
		}

		cmd.Wait()
	}

	return results, nil
}

// SaveResults 保存WIH结果
func (wih *WebInfoHunter) SaveResults(ctx *ScanContext, results []*WIHResult) error {
	// 获取目标域名列表
	targets := strings.Split(ctx.Task.Target, ",")
	domainScanner := NewDomainScanner()
	
	for _, result := range results {
		// 保存发现的子域名（需要验证）
		for _, subdomain := range result.Subdomains {
			subdomain = strings.ToLower(strings.TrimSpace(subdomain))
			if subdomain == "" {
				continue
			}
			
			// 验证域名是否属于任何一个目标域名
			isValidDomain := false
			for _, target := range targets {
				target = strings.TrimSpace(target)
				if domainScanner.isSubdomainOf(subdomain, target) {
					isValidDomain = true
					break
				}
			}
			
			if isValidDomain {
				domain := &models.Domain{
					TaskID: ctx.Task.ID,
					Domain: subdomain,
					Source: "webinfohunter",
				}
				ctx.DB.Where("task_id = ? AND domain = ?", ctx.Task.ID, subdomain).FirstOrCreate(domain)
			}
		}

		// 保存API端点
		for _, api := range result.APIEndpoints {
			url := &models.URL{
				TaskID: ctx.Task.ID,
				URL:    result.URL + api,
				Source: "webinfohunter",
			}
			ctx.DB.Create(url)
		}

		// 如果发现敏感信息，创建漏洞记录
		if len(result.AccessKeys) > 0 || len(result.SecretKeys) > 0 || len(result.APIKeys) > 0 {
			description := ""
			if len(result.AccessKeys) > 0 {
				description += fmt.Sprintf("Access Keys: %d\n", len(result.AccessKeys))
			}
			if len(result.SecretKeys) > 0 {
				description += fmt.Sprintf("Secret Keys: %d\n", len(result.SecretKeys))
			}
			if len(result.APIKeys) > 0 {
				description += fmt.Sprintf("API Keys: %d\n", len(result.APIKeys))
			}
			if len(result.Tokens) > 0 {
				description += fmt.Sprintf("Tokens: %d\n", len(result.Tokens))
			}

			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         result.URL,
				Type:        "sensitive_info",
				Severity:    "high",
				Title:       "JS中发现敏感信息",
				Description: description,
				Solution:    "移除JavaScript中的敏感信息，使用环境变量或安全的配置管理",
			}
			ctx.DB.Create(vuln)
		}

		// 内网IP泄露
		if len(result.InternalIPs) > 0 {
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         result.URL,
				Type:        "info_leak",
				Severity:    "low",
				Title:       "内网IP泄露",
				Description: fmt.Sprintf("发现 %d 个内网IP地址: %s", len(result.InternalIPs), strings.Join(result.InternalIPs, ", ")),
				Solution:    "移除JavaScript中的内网IP地址",
			}
			ctx.DB.Create(vuln)
		}
	}

	return nil
}

// checkWIHInstalled 检查WIH是否已安装
func checkWIHInstalled(binPath string) bool {
	cmd := exec.Command(binPath, "-h")
	err := cmd.Run()
	return err == nil
}

// extractEmails 提取邮箱地址
func extractEmails(content string) []string {
	// 简单的邮箱正则
	emails := []string{}
	seen := make(map[string]bool)

	// 查找邮箱格式
	words := strings.Fields(content)
	for _, word := range words {
		if strings.Contains(word, "@") && strings.Contains(word, ".") {
			// 简单验证
			parts := strings.Split(word, "@")
			if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
				email := strings.ToLower(strings.Trim(word, "\"',;()[]{}"))
				if !seen[email] && isValidEmail(email) {
					seen[email] = true
					emails = append(emails, email)
				}
			}
		}
	}

	return emails
}

// isValidEmail 简单的邮箱验证
func isValidEmail(email string) bool {
	if len(email) < 5 || len(email) > 254 {
		return false
	}
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	return true
}

// readResponseBody 读取响应body
func readResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
