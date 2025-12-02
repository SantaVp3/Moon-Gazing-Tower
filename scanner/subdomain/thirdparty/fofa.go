package thirdparty

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// FofaClient Fofa API 客户端
type FofaClient struct {
	Email   string
	APIKey  string
	BaseURL string
	client  *http.Client
}

// FofaResult Fofa 查询结果
type FofaResult struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg,omitempty"`
	Size    int        `json:"size"`
	Page    int        `json:"page"`
	Mode    string     `json:"mode"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
}

// FofaAsset Fofa 解析后的资产
type FofaAsset struct {
	Host       string `json:"host"`
	IP         string `json:"ip"`
	Port       string `json:"port"`
	Protocol   string `json:"protocol"`
	Domain     string `json:"domain"`
	Title      string `json:"title"`
	Server     string `json:"server"`
	Country    string `json:"country"`
	City       string `json:"city"`
	ASOrg      string `json:"as_org"`
	Banner     string `json:"banner"`
	Cert       string `json:"cert"`
	ICP        string `json:"icp"`
	UpdateTime string `json:"update_time"`
}

// NewFofaClient 创建 Fofa 客户端
func NewFofaClient(email, apiKey string) *FofaClient {
	return &FofaClient{
		Email:   email,
		APIKey:  apiKey,
		BaseURL: "https://fofa.info/api/v1",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IsConfigured 检查是否已配置
func (c *FofaClient) IsConfigured() bool {
	return c.Email != "" && c.APIKey != ""
}

// Search 执行 Fofa 搜索
// fields: host,ip,port,protocol,domain,title,server,country,city,as_org,banner,cert,icp,lastupdatetime
func (c *FofaClient) Search(ctx context.Context, query string, page, size int, fields string) (*FofaResult, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("Fofa API 未配置")
	}

	if fields == "" {
		fields = "host,ip,port,protocol,domain,title,server"
	}

	// Base64 编码查询
	encodedQuery := base64.StdEncoding.EncodeToString([]byte(query))

	// 构建 URL
	u, _ := url.Parse(c.BaseURL + "/search/all")
	params := url.Values{}
	params.Set("email", c.Email)
	params.Set("key", c.APIKey)
	params.Set("qbase64", encodedQuery)
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("size", fmt.Sprintf("%d", size))
	params.Set("fields", fields)
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result FofaResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v, body: %s", err, string(body))
	}

	if result.Error {
		return nil, fmt.Errorf("Fofa API 错误: %s", result.ErrMsg)
	}

	return &result, nil
}

// SearchSubdomains 查询子域名
func (c *FofaClient) SearchSubdomains(ctx context.Context, domain string, maxResults int) ([]FofaAsset, error) {
	query := fmt.Sprintf(`domain="%s"`, domain)
	fields := "host,ip,port,protocol,domain,title,server,cert"

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 1, maxResults, fields)
	if err != nil {
		return nil, err
	}

	return c.parseResults(result, fields), nil
}

// SearchByIP 根据 IP 查询资产
func (c *FofaClient) SearchByIP(ctx context.Context, ip string, maxResults int) ([]FofaAsset, error) {
	query := fmt.Sprintf(`ip="%s"`, ip)
	fields := "host,ip,port,protocol,domain,title,server,banner"

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 1, maxResults, fields)
	if err != nil {
		return nil, err
	}

	return c.parseResults(result, fields), nil
}

// SearchCert 根据证书查询
func (c *FofaClient) SearchCert(ctx context.Context, certKeyword string, maxResults int) ([]FofaAsset, error) {
	query := fmt.Sprintf(`cert="%s"`, certKeyword)
	fields := "host,ip,port,domain,title,cert"

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 1, maxResults, fields)
	if err != nil {
		return nil, err
	}

	return c.parseResults(result, fields), nil
}

// SearchByTitle 根据网站标题查询
func (c *FofaClient) SearchByTitle(ctx context.Context, title string, maxResults int) ([]FofaAsset, error) {
	query := fmt.Sprintf(`title="%s"`, title)
	fields := "host,ip,port,domain,title,server"

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 1, maxResults, fields)
	if err != nil {
		return nil, err
	}

	return c.parseResults(result, fields), nil
}

// SearchByIconHash 根据图标哈希查询
func (c *FofaClient) SearchByIconHash(ctx context.Context, iconHash string, maxResults int) ([]FofaAsset, error) {
	query := fmt.Sprintf(`icon_hash="%s"`, iconHash)
	fields := "host,ip,port,domain,title,server"

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 1, maxResults, fields)
	if err != nil {
		return nil, err
	}

	return c.parseResults(result, fields), nil
}

// parseResults 解析查询结果
func (c *FofaClient) parseResults(result *FofaResult, fields string) []FofaAsset {
	assets := make([]FofaAsset, 0, len(result.Results))
	fieldList := splitFields(fields)

	for _, row := range result.Results {
		asset := FofaAsset{}
		for i, field := range fieldList {
			if i >= len(row) {
				break
			}
			switch field {
			case "host":
				asset.Host = row[i]
			case "ip":
				asset.IP = row[i]
			case "port":
				asset.Port = row[i]
			case "protocol":
				asset.Protocol = row[i]
			case "domain":
				asset.Domain = row[i]
			case "title":
				asset.Title = row[i]
			case "server":
				asset.Server = row[i]
			case "country":
				asset.Country = row[i]
			case "city":
				asset.City = row[i]
			case "as_org":
				asset.ASOrg = row[i]
			case "banner":
				asset.Banner = row[i]
			case "cert":
				asset.Cert = row[i]
			case "icp":
				asset.ICP = row[i]
			case "lastupdatetime":
				asset.UpdateTime = row[i]
			}
		}
		assets = append(assets, asset)
	}

	return assets
}

// GetUserInfo 获取用户信息 (剩余积分等)
func (c *FofaClient) GetUserInfo(ctx context.Context) (map[string]interface{}, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("Fofa API 未配置")
	}

	u, _ := url.Parse(c.BaseURL + "/info/my")
	params := url.Values{}
	params.Set("email", c.Email)
	params.Set("key", c.APIKey)
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}
