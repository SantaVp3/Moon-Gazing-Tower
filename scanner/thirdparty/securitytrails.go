package thirdparty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ZoneClient ZoneTrasfer / DNS历史查询客户端
// 使用 SecurityTrails API
type SecurityTrailsClient struct {
	APIKey  string
	BaseURL string
	client  *http.Client
}

// SecurityTrailsSubdomainsResponse 子域名响应
type SecurityTrailsSubdomainsResponse struct {
	Subdomains      []string `json:"subdomains"`
	SubdomainCount  int      `json:"subdomain_count"`
}

// SecurityTrailsDNSHistoryResponse DNS历史响应
type SecurityTrailsDNSHistoryResponse struct {
	Records []struct {
		Values []struct {
			IP string `json:"ip"`
		} `json:"values"`
		Type      string `json:"type"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
	} `json:"records"`
}

// SecurityTrailsWhoisResponse WHOIS响应
type SecurityTrailsWhoisResponse struct {
	Result struct {
		Items map[string]interface{} `json:"items"`
	} `json:"result"`
}

// NewSecurityTrailsClient 创建 SecurityTrails 客户端
func NewSecurityTrailsClient(apiKey string) *SecurityTrailsClient {
	return &SecurityTrailsClient{
		APIKey:  apiKey,
		BaseURL: "https://api.securitytrails.com/v1",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IsConfigured 检查是否已配置
func (c *SecurityTrailsClient) IsConfigured() bool {
	return c.APIKey != ""
}

// SearchSubdomains 查询子域名
func (c *SecurityTrailsClient) SearchSubdomains(ctx context.Context, domain string) ([]string, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("SecurityTrails API 未配置")
	}

	url := fmt.Sprintf("%s/domain/%s/subdomains", c.BaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("APIKEY", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result SecurityTrailsSubdomainsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	// 拼接完整域名
	fullDomains := make([]string, len(result.Subdomains))
	for i, sub := range result.Subdomains {
		fullDomains[i] = sub + "." + domain
	}

	return fullDomains, nil
}

// GetDNSHistory 获取DNS历史记录
func (c *SecurityTrailsClient) GetDNSHistory(ctx context.Context, domain, recordType string) (*SecurityTrailsDNSHistoryResponse, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("SecurityTrails API 未配置")
	}

	if recordType == "" {
		recordType = "a"
	}

	url := fmt.Sprintf("%s/history/%s/dns/%s", c.BaseURL, domain, recordType)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("APIKEY", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result SecurityTrailsDNSHistoryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &result, nil
}

// GetWhoisHistory 获取WHOIS历史
func (c *SecurityTrailsClient) GetWhoisHistory(ctx context.Context, domain string) (*SecurityTrailsWhoisResponse, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("SecurityTrails API 未配置")
	}

	url := fmt.Sprintf("%s/history/%s/whois", c.BaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("APIKEY", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result SecurityTrailsWhoisResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &result, nil
}

// splitFields 分割字段
func splitFields(fields string) []string {
	return strings.Split(fields, ",")
}
