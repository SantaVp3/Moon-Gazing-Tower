package vulnscan

import (
	"context"
	"crypto/tls"
	"io"
	"moongazing/scanner/core"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"moongazing/config"

	"gopkg.in/yaml.v3"
)

// VulnScanner handles vulnerability scanning
// 类型定义已拆分到 vuln_types.go
// 弱口令爆破已拆分到 weak_password_scanner.go
type VulnScanner struct {
	Timeout     time.Duration
	HTTPClient  *http.Client
	Concurrency int
	Templates   []*POCTemplate
	UserAgent   string
}

// NewVulnScanner creates a new vulnerability scanner
func NewVulnScanner(concurrency int) *VulnScanner {
	if concurrency <= 0 {
		concurrency = core.DefaultVulnScanConcurrency
	}

	return &VulnScanner{
		Timeout: core.VulnScanHTTPTimeout,
		HTTPClient: &http.Client{
			Timeout: core.VulnScanHTTPTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   core.DefaultHTTPTimeout,
					KeepAlive: core.DefaultHTTPTimeout,
				}).DialContext,
				MaxIdleConns:        core.MaxIdleConns,
				MaxIdleConnsPerHost: core.MaxIdleConnsPerHost,
				IdleConnTimeout:     core.IdleConnTimeout,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Concurrency: concurrency,
		Templates:   loadPOCsFromConfig(),
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// loadPOCsFromConfig loads POC templates - minimal built-in for now
func loadPOCsFromConfig() []*POCTemplate {
	// POC templates are typically loaded from files
	// Return minimal built-in templates
	return getMinimalBuiltinPOCs()
}

// getMinimalBuiltinPOCs returns minimal built-in POC templates
func getMinimalBuiltinPOCs() []*POCTemplate {
	return []*POCTemplate{
		// Sensitive file detection
		{
			ID: "sensitive-env-file",
			Info: POCInfo{
				Name:        "环境配置文件泄露",
				Severity:    "high",
				Description: "发现.env配置文件泄露",
			},
			Requests: []POCRequest{
				{
					Method: "GET",
					Path:   []string{"/.env"},
					Matchers: []Matcher{
						{Type: "status", Status: []int{200}},
						{Type: "word", Words: []string{"DB_", "APP_KEY", "SECRET", "PASSWORD"}, Condition: "or"},
					},
					MatchersCondition: "and",
				},
			},
		},
		{
			ID: "git-config-exposure",
			Info: POCInfo{
				Name:        "Git配置泄露",
				Severity:    "medium",
				Description: "发现.git配置文件泄露",
			},
			Requests: []POCRequest{
				{
					Method: "GET",
					Path:   []string{"/.git/config"},
					Matchers: []Matcher{
						{Type: "status", Status: []int{200}},
						{Type: "word", Words: []string{"[core]", "[remote"}},
					},
					MatchersCondition: "and",
				},
			},
		},
	}
}

// GetSensitivePaths returns sensitive paths from config
func GetSensitivePaths() []config.SensitivePathConfig {
	vulnConfig := config.GetVulnConfig()
	if vulnConfig != nil && len(vulnConfig.SensitivePaths) > 0 {
		return vulnConfig.SensitivePaths
	}
	// Return minimal defaults
	return []config.SensitivePathConfig{
		{Path: "/.env", Description: "环境配置", Severity: "high"},
		{Path: "/.git/config", Description: "Git配置", Severity: "medium"},
	}
}

// GetWeakPasswords returns common weak passwords from config
func GetWeakPasswords() []string {
	vulnConfig := config.GetVulnConfig()
	if vulnConfig != nil && len(vulnConfig.WeakPasswords.Common) > 0 {
		return vulnConfig.WeakPasswords.Common
	}
	// Return minimal defaults
	return []string{"admin", "123456", "password", "root", "test"}
}

// GetSensitivePatterns returns sensitive data patterns from config
func GetSensitivePatterns() []config.SensitivePatternConfig {
	vulnConfig := config.GetVulnConfig()
	if vulnConfig != nil && len(vulnConfig.SensitivePatterns) > 0 {
		return vulnConfig.SensitivePatterns
	}
	return nil
}

// LoadPOCFromYAML loads POC template from YAML
func LoadPOCFromYAML(data []byte) (*POCTemplate, error) {
	var template POCTemplate
	err := yaml.Unmarshal(data, &template)
	if err != nil {
		return nil, err
	}

	// Handle both "requests" and "http" fields
	if len(template.HTTP) > 0 && len(template.Requests) == 0 {
		template.Requests = template.HTTP
	}

	return &template, nil
}

// ScanVuln scans a target for vulnerabilities
func (s *VulnScanner) ScanVuln(ctx context.Context, target string, templates []*POCTemplate) *VulnScanResult {
	result := &VulnScanResult{
		Target:    target,
		StartTime: time.Now(),
		Vulns:     make([]VulnResult, 0),
	}

	if templates == nil {
		templates = s.Templates
	}

	// Normalize target URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.Concurrency)

	for _, template := range templates {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(tmpl *POCTemplate) {
			defer wg.Done()
			defer func() { <-semaphore }()

			vulnResult := s.executeTemplate(ctx, target, tmpl)
			if vulnResult != nil {
				mu.Lock()
				result.Vulns = append(result.Vulns, *vulnResult)
				result.TotalFound++
				// Update summary
				switch vulnResult.Severity {
				case "critical":
					result.Summary.Critical++
				case "high":
					result.Summary.High++
				case "medium":
					result.Summary.Medium++
				case "low":
					result.Summary.Low++
				case "info":
					result.Summary.Info++
				}
				mu.Unlock()
			}
			mu.Lock()
			result.TotalChecked++
			mu.Unlock()
		}(template)
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// executeTemplate executes a single POC template
func (s *VulnScanner) executeTemplate(ctx context.Context, target string, template *POCTemplate) *VulnResult {
	for _, request := range template.Requests {
		for _, path := range request.Path {
			url := strings.TrimSuffix(target, "/") + path

			// Build request
			method := strings.ToUpper(request.Method)
			if method == "" {
				method = "GET"
			}

			var body io.Reader
			if request.Body != "" {
				body = strings.NewReader(request.Body)
			}

			req, err := http.NewRequestWithContext(ctx, method, url, body)
			if err != nil {
				continue
			}

			// Set headers
			req.Header.Set("User-Agent", s.UserAgent)
			for key, value := range request.Headers {
				req.Header.Set(key, value)
			}

			// Execute request
			resp, err := s.HTTPClient.Do(req)
			if err != nil {
				continue
			}

			// Read response
			respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()
			if err != nil {
				continue
			}

			// Build response data for matching
			responseData := &ResponseData{
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,
				Body:       string(respBody),
			}

			// Check matchers
			matched := s.checkMatchers(responseData, request.Matchers, request.MatchersCondition)
			if matched {
				// Extract information
				extractedInfo := s.extractInfo(responseData, request.Extractors)

				return &VulnResult{
					Target:        target,
					VulnID:        template.ID,
					Name:          template.Info.Name,
					Severity:      template.Info.Severity,
					Description:   template.Info.Description,
					Reference:     template.Info.Reference,
					Remediation:   template.Info.Remediation,
					MatchedAt:     url,
					ExtractedInfo: extractedInfo,
					Timestamp:     time.Now(),
				}
			}
		}
	}

	return nil
}

// checkMatchers checks if response matches all matchers
func (s *VulnScanner) checkMatchers(resp *ResponseData, matchers []Matcher, condition string) bool {
	if len(matchers) == 0 {
		return false
	}

	if condition == "" {
		condition = "and"
	}

	results := make([]bool, len(matchers))
	for i, matcher := range matchers {
		results[i] = s.checkMatcher(resp, matcher)
	}

	if condition == "or" {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}

	// "and" condition
	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

// checkMatcher checks a single matcher
func (s *VulnScanner) checkMatcher(resp *ResponseData, matcher Matcher) bool {
	var content string
	switch matcher.Part {
	case "header":
		var headerStr string
		for k, v := range resp.Headers {
			headerStr += k + ": " + strings.Join(v, ", ") + "\n"
		}
		content = headerStr
	case "body":
		content = resp.Body
	default:
		// all
		var headerStr string
		for k, v := range resp.Headers {
			headerStr += k + ": " + strings.Join(v, ", ") + "\n"
		}
		content = headerStr + "\n" + resp.Body
	}

	var matched bool
	switch matcher.Type {
	case "status":
		for _, status := range matcher.Status {
			if resp.StatusCode == status {
				matched = true
				break
			}
		}

	case "word":
		matchCount := 0
		for _, word := range matcher.Words {
			if strings.Contains(content, word) {
				matchCount++
			}
		}
		if matcher.Condition == "or" {
			matched = matchCount > 0
		} else {
			matched = matchCount == len(matcher.Words)
		}

	case "regex":
		for _, pattern := range matcher.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(content) {
				matched = true
				if matcher.Condition != "and" {
					break
				}
			} else if matcher.Condition == "and" {
				matched = false
				break
			}
		}

	case "size":
		bodyLen := len(resp.Body)
		for _, size := range matcher.Size {
			if bodyLen == size {
				matched = true
				break
			}
		}
	}

	if matcher.Negative {
		matched = !matched
	}

	return matched
}

// extractInfo extracts information using extractors
func (s *VulnScanner) extractInfo(resp *ResponseData, extractors []Extractor) map[string]any {
	if len(extractors) == 0 {
		return nil
	}

	info := make(map[string]any)
	for _, extractor := range extractors {
		var content string
		switch extractor.Part {
		case "header":
			var headerStr string
			for k, v := range resp.Headers {
				headerStr += k + ": " + strings.Join(v, ", ") + "\n"
			}
			content = headerStr
		default:
			content = resp.Body
		}

		switch extractor.Type {
		case "regex":
			for _, pattern := range extractor.Regex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				matches := re.FindStringSubmatch(content)
				if len(matches) > extractor.Group {
					name := extractor.Name
					if name == "" {
						name = "extracted"
					}
					info[name] = matches[extractor.Group]
				}
			}
		}
	}

	return info
}

// AddCustomPOC adds a custom POC template
func (s *VulnScanner) AddCustomPOC(template *POCTemplate) {
	s.Templates = append(s.Templates, template)
}

// GetTemplateCount returns the number of loaded templates
func (s *VulnScanner) GetTemplateCount() int {
	return len(s.Templates)
}

// FilterTemplatesBySeverity filters templates by severity
func (s *VulnScanner) FilterTemplatesBySeverity(severity string) []*POCTemplate {
	var filtered []*POCTemplate
	for _, t := range s.Templates {
		if strings.EqualFold(t.Info.Severity, severity) {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// FilterTemplatesByTag filters templates by tag
func (s *VulnScanner) FilterTemplatesByTag(tag string) []*POCTemplate {
	var filtered []*POCTemplate
	for _, t := range s.Templates {
		for _, ttag := range t.Info.Tags {
			if strings.EqualFold(ttag, tag) {
				filtered = append(filtered, t)
				break
			}
		}
	}
	return filtered
}
