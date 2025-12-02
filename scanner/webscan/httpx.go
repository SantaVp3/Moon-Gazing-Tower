// httpx.go - HTTP 探测器
// 用于获取子域名的 HTTP 信息：IP、Title、StatusCode、CDN、指纹等

package webscan

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"moongazing/scanner/fingerprint"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/twmb/murmur3"
)

// HttpxScanner HTTP 探测器
type HttpxScanner struct {
	client            *http.Client
	fingerprintScanner *fingerprint.FingerprintScanner
	timeout           time.Duration
	threads           int
	followRedirect    bool
}

// HttpxResult HTTP 探测结果
type HttpxResult struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	IPs           []string `json:"ips"`
	Port          string   `json:"port"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	ContentLength int      `json:"content_length"`
	ContentType   string   `json:"content_type"`
	WebServer     string   `json:"web_server"`
	Technologies  []string `json:"technologies"`
	CDN           bool     `json:"cdn"`
	CDNName       string   `json:"cdn_name"`
	Favicon       string   `json:"favicon"`       // favicon hash (mmh3)
	FaviconData   []byte   `json:"favicon_data"`
	RawHeaders    string   `json:"raw_headers"`
	Body          string   `json:"body"`
	Scheme        string   `json:"scheme"`
	Error         string   `json:"error,omitempty"`
	ResponseTime  time.Duration `json:"response_time"`
}

// NewHttpxScanner 创建 HTTP 探测器
func NewHttpxScanner(threads int) *HttpxScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &HttpxScanner{
		client:            client,
		fingerprintScanner: fingerprint.NewFingerprintScanner(threads),
		timeout:           15 * time.Second,
		threads:           threads,
		followRedirect:    true,
	}
}

// Probe 探测单个目标
func (h *HttpxScanner) Probe(ctx context.Context, target string) *HttpxResult {
	result := &HttpxResult{
		Host: target,
	}

	// 1. DNS 解析获取 IP
	ips, err := net.LookupIP(target)
	if err == nil {
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				result.IPs = append(result.IPs, ipv4.String())
			}
		}
		if len(result.IPs) > 0 {
			result.IP = result.IPs[0]
		}
	}

	// 2. 检测 CDN
	result.CDN, result.CDNName = h.detectCDN(target, result.IPs)

	// 3. HTTP/HTTPS 探测
	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s", scheme, target)
		
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		
		// 设置常用 headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Connection", "close")
		
		startTime := time.Now()
		resp, err := h.client.Do(req)
		if err != nil {
			continue
		}
		
		result.ResponseTime = time.Since(startTime)
		result.URL = url
		result.Scheme = scheme
		result.StatusCode = resp.StatusCode
		result.ContentType = resp.Header.Get("Content-Type")
		result.WebServer = resp.Header.Get("Server")
		
		// 读取响应头
		var headerBuilder strings.Builder
		for key, values := range resp.Header {
			for _, value := range values {
				headerBuilder.WriteString(fmt.Sprintf("%s: %s\n", key, value))
			}
		}
		result.RawHeaders = headerBuilder.String()
		
		// 读取响应体
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 限制 1MB
		resp.Body.Close()
		if err == nil {
			result.Body = string(bodyBytes)
			result.ContentLength = len(bodyBytes)
			
			// 提取 Title
			result.Title = h.extractTitle(result.Body)
		}
		
		// 4. 指纹识别
		result.Technologies = h.detectFingerprint(ctx, url, result.Body, result.RawHeaders, result.Title, result.WebServer)
		
		// 5. 获取 favicon
		faviconURL := fmt.Sprintf("%s://%s/favicon.ico", scheme, target)
		result.Favicon, result.FaviconData = h.getFavicon(ctx, faviconURL)
		
		break // 成功则不再尝试另一个协议
	}
	
	return result
}

// ProbeMultiple 批量探测多个目标
func (h *HttpxScanner) ProbeMultiple(ctx context.Context, targets []string) []*HttpxResult {
	results := make([]*HttpxResult, 0, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// 使用信号量控制并发
	semaphore := make(chan struct{}, h.threads)
	
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break
		default:
		}
		
		wg.Add(1)
		semaphore <- struct{}{}
		
		go func(t string) {
			defer func() {
				<-semaphore
				wg.Done()
			}()
			
			result := h.Probe(ctx, t)
			
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(target)
	}
	
	wg.Wait()
	return results
}

// extractTitle 提取网页标题
func (h *HttpxScanner) extractTitle(body string) string {
	// 使用正则表达式提取 title
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// 限制长度
		if len(title) > 200 {
			title = title[:200] + "..."
		}
		return title
	}
	return ""
}

// detectCDN 检测 CDN
func (h *HttpxScanner) detectCDN(host string, ips []string) (bool, string) {
	// 1. 通过 CNAME 检测
	cnames, err := net.LookupCNAME(host)
	if err == nil && cnames != "" {
		cdnCnames := map[string]string{
			"cloudflare":     "Cloudflare",
			"cloudfront":     "CloudFront",
			"akamai":         "Akamai",
			"fastly":         "Fastly",
			"cdn.":           "CDN",
			"cdnify":         "CDNify",
			"edgecast":       "EdgeCast",
			"azureedge":      "Azure CDN",
			"googleusercontent": "Google Cloud CDN",
			"kunlunaq":       "阿里云CDN",
			"kunluncan":      "阿里云CDN",
			"alikunlun":      "阿里云CDN",
			"kunlunsl":       "阿里云CDN",
			"cdngslb":        "阿里云CDN",
			"tbcache":        "阿里云CDN",
			"alicdn":         "阿里云CDN",
			"aliyuncs":       "阿里云",
			"qiniu":          "七牛云CDN",
			"qiniudns":       "七牛云CDN",
			"qbox":           "七牛云CDN",
			"baidubce":       "百度云CDN",
			"bcebos":         "百度云CDN",
			"bdydns":         "百度云CDN",
			"tcdn":           "腾讯云CDN",
			"dnsv1":          "腾讯云CDN",
			"tdnsv5":         "腾讯云CDN",
			"cdn.myqcloud":   "腾讯云CDN",
			"wangsucdn":      "网宿CDN",
			"wsglb":          "网宿CDN",
			"chinanetcenter": "网宿CDN",
			"lxdns":          "蓝汛CDN",
			"chinacache":     "蓝汛CDN",
			"speedcdns":      "加速乐CDN",
			"jiashule":       "加速乐CDN",
			"yunjiasu":       "百度云加速",
			"yundunddos":     "云盾CDN",
			"vercel-dns":     "Vercel",
			"incapdns":       "Imperva",
			"edgesuite":      "Akamai",
		}
		
		cnameLower := strings.ToLower(cnames)
		for pattern, name := range cdnCnames {
			if strings.Contains(cnameLower, pattern) {
				return true, name
			}
		}
	}
	
	// 2. 通过 IP 数量判断（多个 IP 可能是 CDN）
	if len(ips) > 3 {
		return true, "Unknown CDN"
	}
	
	// 3. 通过 IP 范围检测（常见 CDN IP 段）
	// TODO: 添加更多 CDN IP 范围检测
	
	return false, ""
}

// detectFingerprint 检测指纹
func (h *HttpxScanner) detectFingerprint(ctx context.Context, url, body, headers, title, server string) []string {
	// 使用指纹扫描器
	fpResult := h.fingerprintScanner.ScanFingerprint(ctx, url)
	
	technologies := make([]string, 0)
	for _, fp := range fpResult.Fingerprints {
		technologies = append(technologies, fp.Name)
	}
	
	return technologies
}

// getFavicon 获取 favicon 并计算 hash
func (h *HttpxScanner) getFavicon(ctx context.Context, faviconURL string) (string, []byte) {
	req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
	if err != nil {
		return "", nil
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := h.client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return "", nil
	}
	
	data, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024)) // 限制 100KB
	if err != nil {
		return "", nil
	}
	
	// 计算 mmh3 hash (和 shodan/fofa 兼容)
	hash := h.calculateFaviconHash(data)
	
	return hash, data
}

// calculateFaviconHash 计算 favicon 的 mmh3 hash
func (h *HttpxScanner) calculateFaviconHash(data []byte) string {
	// 先 base64 编码
	b64 := base64.StdEncoding.EncodeToString(data)
	
	// 计算 mmh3 hash
	hasher := murmur3.New32()
	hasher.Write([]byte(b64))
	hash := int32(hasher.Sum32())
	
	return fmt.Sprintf("%d", hash)
}

// EnrichSubdomain 丰富子域名信息
// 这是主要入口，用于在子域名扫描后获取完整信息
func (h *HttpxScanner) EnrichSubdomain(ctx context.Context, subdomain string) *HttpxResult {
	return h.Probe(ctx, subdomain)
}

// EnrichSubdomains 批量丰富子域名信息
func (h *HttpxScanner) EnrichSubdomains(ctx context.Context, subdomains []string) []*HttpxResult {
	return h.ProbeMultiple(ctx, subdomains)
}
