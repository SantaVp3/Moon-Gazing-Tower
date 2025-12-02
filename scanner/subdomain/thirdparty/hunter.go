package thirdparty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HunterClient Hunter API 客户端 (奇安信)
type HunterClient struct {
	APIKey  string
	BaseURL string
	client  *http.Client
}

// HunterResponse Hunter API 响应
type HunterResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    *HunterData `json:"data"`
}

// HunterData Hunter 数据
type HunterData struct {
	Total        int           `json:"total"`
	Time         int           `json:"time"`
	ConsumeQuota string        `json:"consume_quota"`
	RestQuota    string        `json:"rest_quota"`
	Arr          []HunterAsset `json:"arr"`
}

// HunterAsset Hunter 资产
type HunterAsset struct {
	URL          string `json:"url"`
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Domain       string `json:"domain"`
	Protocol     string `json:"protocol"`
	WebTitle     string `json:"web_title"`
	StatusCode   int    `json:"status_code"`
	Company      string `json:"company"`
	Number       string `json:"number"` // ICP 备案号
	Country      string `json:"country"`
	Province     string `json:"province"`
	City         string `json:"city"`
	ISP          string `json:"isp"`
	Banner       string `json:"banner"`
	BaseProtocol string `json:"base_protocol"`
	Os           string `json:"os"`
	Component    []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"component"`
	UpdateTime string `json:"updated_at"`
	IsRisk     string `json:"is_risk"`
	IsRiskPro  string `json:"is_risk_protocol"`
}

// NewHunterClient 创建 Hunter 客户端
func NewHunterClient(apiKey string) *HunterClient {
	return &HunterClient{
		APIKey:  apiKey,
		BaseURL: "https://hunter.qianxin.com/openApi",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IsConfigured 检查是否已配置
func (c *HunterClient) IsConfigured() bool {
	return c.APIKey != ""
}

// Search 执行 Hunter 搜索
func (c *HunterClient) Search(ctx context.Context, query string, page, pageSize int, startTime, endTime string) (*HunterData, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("Hunter API 未配置")
	}

	u, _ := url.Parse(c.BaseURL + "/search")
	params := url.Values{}
	params.Set("api-key", c.APIKey)
	params.Set("search", query)
	params.Set("page", fmt.Sprintf("%d", page))
	params.Set("page_size", fmt.Sprintf("%d", pageSize))
	params.Set("is_web", "3") // 1: web资产 2: 非web资产 3: 全部

	if startTime != "" {
		params.Set("start_time", startTime)
	}
	if endTime != "" {
		params.Set("end_time", endTime)
	}

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

	var result HunterResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	if result.Code != 200 {
		return nil, fmt.Errorf("Hunter API 错误: %s", result.Message)
	}

	return result.Data, nil
}

// SearchSubdomains 查询子域名
func (c *HunterClient) SearchSubdomains(ctx context.Context, domain string, maxResults int) ([]HunterAsset, error) {
	query := fmt.Sprintf(`domain.suffix="%s"`, domain)

	if maxResults <= 0 {
		maxResults = 100
	}

	data, err := c.Search(ctx, query, 1, maxResults, "", "")
	if err != nil {
		return nil, err
	}

	if data == nil {
		return []HunterAsset{}, nil
	}

	return data.Arr, nil
}

// SearchByIP 根据 IP 查询资产
func (c *HunterClient) SearchByIP(ctx context.Context, ip string, maxResults int) ([]HunterAsset, error) {
	query := fmt.Sprintf(`ip="%s"`, ip)

	if maxResults <= 0 {
		maxResults = 100
	}

	data, err := c.Search(ctx, query, 1, maxResults, "", "")
	if err != nil {
		return nil, err
	}

	if data == nil {
		return []HunterAsset{}, nil
	}

	return data.Arr, nil
}

// SearchByICP 根据 ICP 备案号查询
func (c *HunterClient) SearchByICP(ctx context.Context, icp string, maxResults int) ([]HunterAsset, error) {
	query := fmt.Sprintf(`icp.number="%s"`, icp)

	if maxResults <= 0 {
		maxResults = 100
	}

	data, err := c.Search(ctx, query, 1, maxResults, "", "")
	if err != nil {
		return nil, err
	}

	if data == nil {
		return []HunterAsset{}, nil
	}

	return data.Arr, nil
}

// SearchByCompany 根据公司名查询
func (c *HunterClient) SearchByCompany(ctx context.Context, company string, maxResults int) ([]HunterAsset, error) {
	query := fmt.Sprintf(`icp.name="%s"`, company)

	if maxResults <= 0 {
		maxResults = 100
	}

	data, err := c.Search(ctx, query, 1, maxResults, "", "")
	if err != nil {
		return nil, err
	}

	if data == nil {
		return []HunterAsset{}, nil
	}

	return data.Arr, nil
}

// GetAccountInfo 获取账户信息
func (c *HunterClient) GetAccountInfo(ctx context.Context) (map[string]interface{}, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("Hunter API 未配置")
	}

	// Hunter 没有专门的账户信息接口，通过搜索响应获取配额信息
	data, err := c.Search(ctx, `ip="1.1.1.1"`, 1, 1, "", "")
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"rest_quota":    data.RestQuota,
		"consume_quota": data.ConsumeQuota,
	}, nil
}
