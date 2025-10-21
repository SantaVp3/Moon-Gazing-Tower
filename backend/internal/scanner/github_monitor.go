package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// GithubMonitor Github监控器
type GithubMonitor struct {
	client *http.Client
	token  string
}

// NewGithubMonitor 创建Github监控器
func NewGithubMonitor(token string) *GithubMonitor {
	return &GithubMonitor{
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		token: token,
	}
}

// GithubSearchResult Github搜索结果
type GithubSearchResult struct {
	TotalCount int `json:"total_count"`
	Items      []struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		HTMLURL     string `json:"html_url"`
		Repository  struct {
			FullName    string `json:"full_name"`
			Description string `json:"description"`
			HTMLURL     string `json:"html_url"`
		} `json:"repository"`
		Score float64 `json:"score"`
	} `json:"items"`
}

// SearchKeyword 搜索关键字
func (gm *GithubMonitor) SearchKeyword(keyword string, maxResults int) (*GithubSearchResult, error) {
	if maxResults <= 0 {
		maxResults = 30
	}
	if maxResults > 100 {
		maxResults = 100
	}

	// 构建搜索URL
	query := url.QueryEscape(keyword)
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=%d&sort=indexed&order=desc", query, maxResults)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置认证头
	if gm.token != "" {
		req.Header.Set("Authorization", "token "+gm.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "ARL-Scanner")

	resp, err := gm.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return nil, fmt.Errorf("API rate limit exceeded or authentication required")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result GithubSearchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SearchMultipleKeywords 搜索多个关键字
func (gm *GithubMonitor) SearchMultipleKeywords(keywords []string) (map[string]*GithubSearchResult, error) {
	results := make(map[string]*GithubSearchResult)

	for _, keyword := range keywords {
		result, err := gm.SearchKeyword(keyword, 30)
		if err != nil {
			// 继续处理其他关键字
			continue
		}
		results[keyword] = result

		// 避免触发rate limit
		time.Sleep(2 * time.Second)
	}

	return results, nil
}

// SearchSensitiveInfo 搜索敏感信息
func (gm *GithubMonitor) SearchSensitiveInfo(domain string) (*GithubSearchResult, error) {
	// 构建敏感信息搜索查询
	queries := []string{
		fmt.Sprintf("%s password", domain),
		fmt.Sprintf("%s api_key", domain),
		fmt.Sprintf("%s secret", domain),
		fmt.Sprintf("%s token", domain),
		fmt.Sprintf("%s aws_access_key", domain),
	}

	var allItems []struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		HTMLURL     string `json:"html_url"`
		Repository  struct {
			FullName    string `json:"full_name"`
			Description string `json:"description"`
			HTMLURL     string `json:"html_url"`
		} `json:"repository"`
		Score float64 `json:"score"`
	}

	for _, query := range queries {
		result, err := gm.SearchKeyword(query, 10)
		if err != nil {
			continue
		}
		allItems = append(allItems, result.Items...)
		time.Sleep(2 * time.Second)
	}

	return &GithubSearchResult{
		TotalCount: len(allItems),
		Items:      allItems,
	}, nil
}

// MonitorKeywords 监控关键字
func (gm *GithubMonitor) MonitorKeywords(ctx *ScanContext, keywords []string) error {
	ctx.Logger.Printf("Monitoring %d keywords on Github", len(keywords))

	results, err := gm.SearchMultipleKeywords(keywords)
	if err != nil {
		return err
	}

	// 保存结果
	for keyword, result := range results {
		ctx.Logger.Printf("Keyword '%s' found %d results", keyword, result.TotalCount)

		for _, item := range result.Items {
			// 检查是否包含敏感信息
			severity := "low"
			title := fmt.Sprintf("Github发现关键字: %s", keyword)
			description := fmt.Sprintf("Repository: %s\nFile: %s\nURL: %s",
				item.Repository.FullName,
				item.Path,
				item.HTMLURL)

			// 判断严重性
			lowerKeyword := strings.ToLower(keyword)
			if strings.Contains(lowerKeyword, "password") ||
				strings.Contains(lowerKeyword, "secret") ||
				strings.Contains(lowerKeyword, "key") {
				severity = "high"
			}

			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         item.HTMLURL,
				Type:        "github_leak",
				Severity:    severity,
				Title:       title,
				Description: description,
				Reference:   item.Repository.HTMLURL,
				Solution:    "检查Github仓库中的敏感信息泄露，及时删除或修改凭据",
			}
			ctx.DB.Create(vuln)
		}
	}

	return nil
}

// GetFileContent 获取文件内容
func (gm *GithubMonitor) GetFileContent(repo, path, ref string) (string, error) {
	if ref == "" {
		ref = "master"
	}

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s?ref=%s", repo, path, ref)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	if gm.token != "" {
		req.Header.Set("Authorization", "token "+gm.token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3.raw")
	req.Header.Set("User-Agent", "ARL-Scanner")

	resp, err := gm.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// CheckLeakedCredentials 检查泄露的凭据
func (gm *GithubMonitor) CheckLeakedCredentials(content string) map[string][]string {
	leaks := make(map[string][]string)

	// AWS Access Key
	if keys := extractPattern(content, `AKIA[0-9A-Z]{16}`); len(keys) > 0 {
		leaks["aws_access_key"] = keys
	}

	// AWS Secret Key
	if keys := extractPattern(content, `[0-9a-zA-Z/+]{40}`); len(keys) > 0 {
		leaks["aws_secret_key"] = keys
	}

	// API Keys (通用格式)
	if keys := extractPattern(content, `[a-zA-Z0-9_-]{32,}`); len(keys) > 0 {
		leaks["api_key"] = keys
	}

	// JWT Token
	if keys := extractPattern(content, `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`); len(keys) > 0 {
		leaks["jwt_token"] = keys
	}

	// 私钥
	if strings.Contains(content, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(content, "BEGIN PRIVATE KEY") {
		leaks["private_key"] = []string{"Found private key"}
	}

	return leaks
}

// extractPattern 提取模式匹配
func extractPattern(content, pattern string) []string {
	// 简单实现，实际应使用regexp
	var results []string
	// TODO: 使用正则表达式匹配
	return results
}
