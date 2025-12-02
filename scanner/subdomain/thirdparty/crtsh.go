package thirdparty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CrtShClient 证书透明度查询客户端 (crt.sh)
type CrtShClient struct {
	BaseURL string
	client  *http.Client
}

// CrtShResult crt.sh 查询结果
type CrtShResult struct {
	IssuerCAID        int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	CommonName        string `json:"common_name"`
	NameValue         string `json:"name_value"`
	ID                int    `json:"id"`
	EntryTimestamp    string `json:"entry_timestamp"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	SerialNumber      string `json:"serial_number"`
}

// NewCrtShClient 创建 crt.sh 客户端
func NewCrtShClient() *CrtShClient {
	return &CrtShClient{
		BaseURL: "https://crt.sh",
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// SearchSubdomains 通过证书透明度查询子域名
func (c *CrtShClient) SearchSubdomains(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("%s/?q=%%.%s&output=json", c.BaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []CrtShResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	// 去重
	subdomainMap := make(map[string]bool)
	for _, r := range results {
		// name_value 可能包含多个域名，用换行分隔
		domains := splitDomains(r.NameValue)
		for _, d := range domains {
			if d != "" && !subdomainMap[d] {
				subdomainMap[d] = true
			}
		}
		if r.CommonName != "" && !subdomainMap[r.CommonName] {
			subdomainMap[r.CommonName] = true
		}
	}

	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

// GetCertificates 获取完整证书信息
func (c *CrtShClient) GetCertificates(ctx context.Context, domain string) ([]CrtShResult, error) {
	url := fmt.Sprintf("%s/?q=%%.%s&output=json", c.BaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []CrtShResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return results, nil
}

// splitDomains 分割域名（处理换行符）
func splitDomains(nameValue string) []string {
	var domains []string
	current := ""
	for _, c := range nameValue {
		if c == '\n' || c == '\r' {
			if current != "" {
				domains = append(domains, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		domains = append(domains, current)
	}
	return domains
}
