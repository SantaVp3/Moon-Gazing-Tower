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

// QuakeClient Quake API 客户端 (360)
type QuakeClient struct {
	APIKey  string
	BaseURL string
	client  *http.Client
}

// QuakeResponse Quake API 响应
type QuakeResponse struct {
	Code    int          `json:"code"`
	Message string       `json:"message"`
	Data    []QuakeAsset `json:"data"`
	Meta    *QuakeMeta   `json:"meta"`
}

// QuakeMeta Quake 元数据
type QuakeMeta struct {
	Total        int    `json:"total"`
	PaginationID string `json:"pagination_id"`
}

// QuakeAsset Quake 资产
type QuakeAsset struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Hostname  string `json:"hostname"`
	Domain    string `json:"domain"`
	Transport string `json:"transport"`
	Service   struct {
		Name     string `json:"name"`
		Product  string `json:"product"`
		Version  string `json:"version"`
		Response string `json:"response"`
		HTTP     struct {
			Title      string   `json:"title"`
			StatusCode int      `json:"status_code"`
			Server     string   `json:"server"`
			Host       string   `json:"host"`
			Path       string   `json:"path"`
			Favicon    *Favicon `json:"favicon"`
		} `json:"http"`
		Cert string `json:"cert"`
		TLS  struct {
			Handshake struct {
				Extensions struct {
					ServerName string `json:"server_name"`
				} `json:"extensions"`
			} `json:"handshake_log"`
		} `json:"tls-alpn"`
	} `json:"service"`
	Location struct {
		Country   string `json:"country_cn"`
		Province  string `json:"province_cn"`
		City      string `json:"city_cn"`
		ISP       string `json:"isp"`
		CountryEn string `json:"country_en"`
	} `json:"location"`
	ASInfo struct {
		ASN  int    `json:"asn"`
		Org  string `json:"organization"`
		Name string `json:"name"`
	} `json:"asn"`
	Time       string   `json:"time"`
	Components []string `json:"components"`
}

// Favicon 网站图标信息
type Favicon struct {
	Hash     string `json:"hash"`
	Location string `json:"location"`
	Data     string `json:"data"`
}

// QuakeUserInfo 用户信息响应
type QuakeUserInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		ID       string `json:"id"`
		Username string `json:"user"`
		Email    string `json:"email"`
		Credit   int    `json:"credit"`     // 永久积分
		MonthCredit int `json:"month_remaining_credit"` // 月度积分
		Role     struct {
			Fullname string `json:"fullname"`
		} `json:"role"`
	} `json:"data"`
}

// NewQuakeClient 创建 Quake 客户端
func NewQuakeClient(apiKey string) *QuakeClient {
	return &QuakeClient{
		APIKey:  apiKey,
		BaseURL: "https://quake.360.net/api/v3",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IsConfigured 检查是否已配置
func (c *QuakeClient) IsConfigured() bool {
	return c.APIKey != ""
}

// Search 执行 Quake 搜索
func (c *QuakeClient) Search(ctx context.Context, query string, start, size int) (*QuakeResponse, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("Quake API 未配置")
	}

	reqBody := map[string]interface{}{
		"query":      query,
		"start":      start,
		"size":       size,
		"include":    []string{"ip", "port", "hostname", "domain", "transport", "service", "location", "asn", "time", "components"},
		"latest":     true,
		"shortcuts":  []string{"610ce2adb1a2e3e1632e67b1"},
	}

	jsonBody, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/search/quake_service", strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-QuakeToken", c.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result QuakeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("Quake API 错误: %s", result.Message)
	}

	return &result, nil
}

// SearchSubdomains 查询子域名
func (c *QuakeClient) SearchSubdomains(ctx context.Context, domain string, maxResults int) ([]QuakeAsset, error) {
	query := fmt.Sprintf(`domain:"%s"`, domain)

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 0, maxResults)
	if err != nil {
		return nil, err
	}

	return result.Data, nil
}

// SearchByIP 根据 IP 查询资产
func (c *QuakeClient) SearchByIP(ctx context.Context, ip string, maxResults int) ([]QuakeAsset, error) {
	query := fmt.Sprintf(`ip:"%s"`, ip)

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 0, maxResults)
	if err != nil {
		return nil, err
	}

	return result.Data, nil
}

// SearchByCert 根据证书查询
func (c *QuakeClient) SearchByCert(ctx context.Context, certKeyword string, maxResults int) ([]QuakeAsset, error) {
	query := fmt.Sprintf(`cert:"%s"`, certKeyword)

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 0, maxResults)
	if err != nil {
		return nil, err
	}

	return result.Data, nil
}

// SearchByFaviconHash 根据图标哈希查询
func (c *QuakeClient) SearchByFaviconHash(ctx context.Context, hash string, maxResults int) ([]QuakeAsset, error) {
	query := fmt.Sprintf(`favicon:"%s"`, hash)

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 0, maxResults)
	if err != nil {
		return nil, err
	}

	return result.Data, nil
}

// SearchByTitle 根据网站标题查询
func (c *QuakeClient) SearchByTitle(ctx context.Context, title string, maxResults int) ([]QuakeAsset, error) {
	query := fmt.Sprintf(`title:"%s"`, title)

	if maxResults <= 0 {
		maxResults = 100
	}

	result, err := c.Search(ctx, query, 0, maxResults)
	if err != nil {
		return nil, err
	}

	return result.Data, nil
}

// GetUserInfo 获取用户信息
func (c *QuakeClient) GetUserInfo(ctx context.Context) (*QuakeUserInfo, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("Quake API 未配置")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+"/user/info", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-QuakeToken", c.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result QuakeUserInfo
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	return &result, nil
}
