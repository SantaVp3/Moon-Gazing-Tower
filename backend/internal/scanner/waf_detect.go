package scanner

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

// WAFDetector WAF检测器
type WAFDetector struct {
	client *http.Client
}

// NewWAFDetector 创建WAF检测器
func NewWAFDetector() *WAFDetector {
	return &WAFDetector{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// WAFSignature WAF特征
type WAFSignature struct {
	Name    string
	Headers map[string]string
	Cookies []string
	Body    []string
}

// Detect 检测WAF
func (d *WAFDetector) Detect(url string) []string {
	var detectedWAFs []string

	// 发送测试请求
	resp, err := d.client.Get(url)
	if err != nil {
		return detectedWAFs
	}
	defer resp.Body.Close()

	// WAF特征库
	signatures := []WAFSignature{
		{
			Name: "Cloudflare",
			Headers: map[string]string{
				"server":          "cloudflare",
				"cf-ray":          "",
				"cf-cache-status": "",
			},
		},
		{
			Name: "AWS WAF",
			Headers: map[string]string{
				"x-amzn-requestid": "",
				"x-amzn-errortype": "",
			},
		},
		{
			Name: "Azure WAF",
			Headers: map[string]string{
				"x-azure-ref": "",
			},
		},
		{
			Name: "Akamai",
			Headers: map[string]string{
				"server": "AkamaiGHost",
			},
		},
		{
			Name: "Incapsula",
			Headers: map[string]string{
				"x-cdn": "Incapsula",
			},
			Cookies: []string{"incap_ses", "visid_incap"},
		},
		{
			Name: "Sucuri",
			Headers: map[string]string{
				"server":        "Sucuri",
				"x-sucuri-id":   "",
				"x-sucuri-cache": "",
			},
		},
		{
			Name: "ModSecurity",
			Headers: map[string]string{
				"server": "Mod_Security",
			},
		},
		{
			Name: "Barracuda",
			Headers: map[string]string{
				"server": "Barracuda",
			},
			Cookies: []string{"barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"},
		},
		{
			Name: "F5 BIG-IP",
			Headers: map[string]string{
				"server": "BigIP",
			},
			Cookies: []string{"BIGipServer", "TS"},
		},
		{
			Name: "Fortinet FortiWeb",
			Headers: map[string]string{
				"server": "FortiWeb",
			},
			Cookies: []string{"FORTIWAFSID"},
		},
		{
			Name: "阿里云盾",
			Headers: map[string]string{
				"ali-swift-global-savetime": "",
				"eagleid":                   "",
			},
		},
		{
			Name: "腾讯云WAF",
			Headers: map[string]string{
				"waf-powered-by": "Tencent",
			},
		},
		{
			Name: "安全狗",
			Headers: map[string]string{
				"server": "Safedog",
			},
			Cookies: []string{"safedog-flow-item"},
		},
		{
			Name: "云锁",
			Headers: map[string]string{
				"server": "Yunsuo",
			},
		},
	}

	// 检查特征
	for _, sig := range signatures {
		if d.matchSignature(resp, sig) {
			detectedWAFs = append(detectedWAFs, sig.Name)
		}
	}

	// 发送恶意请求测试
	if d.testMaliciousRequest(url) {
		if len(detectedWAFs) == 0 {
			detectedWAFs = append(detectedWAFs, "Unknown WAF")
		}
	}

	return detectedWAFs
}

// matchSignature 匹配特征
func (d *WAFDetector) matchSignature(resp *http.Response, sig WAFSignature) bool {
	// 检查Headers
	for header, value := range sig.Headers {
		headerValue := resp.Header.Get(header)
		if headerValue != "" {
			if value == "" || strings.Contains(strings.ToLower(headerValue), strings.ToLower(value)) {
				return true
			}
		}
	}

	// 检查Cookies
	for _, cookieName := range sig.Cookies {
		for _, cookie := range resp.Cookies() {
			if strings.Contains(cookie.Name, cookieName) {
				return true
			}
		}
	}

	return false
}

// testMaliciousRequest 测试恶意请求
func (d *WAFDetector) testMaliciousRequest(baseURL string) bool {
	// 测试SQL注入
	testURL := baseURL + "?id=1' OR '1'='1"
	resp, err := d.client.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 如果返回403或类似状态码，可能有WAF
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 419 {
		return true
	}

	return false
}
