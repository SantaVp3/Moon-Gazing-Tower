package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/reconmaster/backend/internal/models"
)

// HostCollisionScanner Host碰撞扫描器
type HostCollisionScanner struct {
	client *http.Client
}

// NewHostCollisionScanner 创建Host碰撞扫描器
func NewHostCollisionScanner() *HostCollisionScanner {
	return &HostCollisionScanner{
		client: &http.Client{
			Timeout: 10,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Scan 执行Host碰撞检测
func (hcs *HostCollisionScanner) Scan(ctx *ScanContext) error {
	// 获取所有域名和对应的IP
	var domains []models.Domain
	ctx.DB.Where("task_id = ? AND ip_address != ''", ctx.Task.ID).Find(&domains)

	ctx.Logger.Printf("Checking host collision for %d domains", len(domains))

	for _, domain := range domains {
		// 直接访问IP
		ipResponse := hcs.requestByIP(domain.IPAddress, 80)
		if ipResponse == nil {
			continue
		}

		// 使用Host头访问
		hostResponse := hcs.requestWithHost(domain.IPAddress, 80, domain.Domain)
		if hostResponse == nil {
			continue
		}

		// 比较响应
		if hcs.isDifferent(ipResponse, hostResponse) {
			// 发现Host碰撞漏洞
			vuln := &models.Vulnerability{
				TaskID:      ctx.Task.ID,
				URL:         fmt.Sprintf("http://%s", domain.IPAddress),
				Type:        "host_collision",
				Severity:    "medium",
				Title:       "Host头碰撞",
				Description: fmt.Sprintf("IP %s 对不同的Host头返回不同的内容。可能存在虚拟主机配置不当。测试域名: %s", domain.IPAddress, domain.Domain),
				Solution:    "检查虚拟主机配置，确保正确配置Host头验证",
			}
			ctx.DB.Create(vuln)
			ctx.Logger.Printf("Host collision found: %s -> %s", domain.IPAddress, domain.Domain)
		}
	}

	return nil
}

// requestByIP 直接通过IP访问
func (hcs *HostCollisionScanner) requestByIP(ip string, port int) *http.Response {
	url := fmt.Sprintf("http://%s:%d/", ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := hcs.client.Do(req)
	if err != nil {
		return nil
	}

	return resp
}

// requestWithHost 使用指定Host头访问
func (hcs *HostCollisionScanner) requestWithHost(ip string, port int, host string) *http.Response {
	url := fmt.Sprintf("http://%s:%d/", ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Host = host
	req.Header.Set("Host", host)

	resp, err := hcs.client.Do(req)
	if err != nil {
		return nil
	}

	return resp
}

// isDifferent 比较两个响应是否不同
func (hcs *HostCollisionScanner) isDifferent(resp1, resp2 *http.Response) bool {
	defer resp1.Body.Close()
	defer resp2.Body.Close()

	// 比较状态码
	if resp1.StatusCode != resp2.StatusCode {
		return true
	}

	// 比较Content-Length
	if resp1.ContentLength != resp2.ContentLength && resp1.ContentLength > 0 && resp2.ContentLength > 0 {
		return true
	}

	// 读取body并比较
	body1, err1 := io.ReadAll(resp1.Body)
	body2, err2 := io.ReadAll(resp2.Body)

	if err1 != nil || err2 != nil {
		return false
	}

	// 如果长度差异很大，认为是不同的
	if abs(len(body1)-len(body2)) > 100 {
		return true
	}

	// 比较关键特征
	return hcs.compareFeatures(string(body1), string(body2))
}

// compareFeatures 比较响应特征
func (hcs *HostCollisionScanner) compareFeatures(body1, body2 string) bool {
	// 提取title
	title1 := extractTitleFromBody(body1)
	title2 := extractTitleFromBody(body2)

	if title1 != title2 && title1 != "" && title2 != "" {
		return true
	}

	// 比较关键字出现次数
	keywords := []string{"html", "body", "script", "div"}
	for _, keyword := range keywords {
		count1 := strings.Count(strings.ToLower(body1), keyword)
		count2 := strings.Count(strings.ToLower(body2), keyword)
		if abs(count1-count2) > 5 {
			return true
		}
	}

	return false
}

// extractTitleFromBody 从body提取title
func extractTitleFromBody(body string) string {
	start := strings.Index(strings.ToLower(body), "<title>")
	end := strings.Index(strings.ToLower(body), "</title>")
	
	if start >= 0 && end > start {
		return body[start+7 : end]
	}
	
	return ""
}

// abs 绝对值
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
