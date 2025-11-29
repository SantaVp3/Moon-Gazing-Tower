package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"moongazing/config"

	"gopkg.in/yaml.v3"
)

// VulnResult represents a vulnerability scan result
type VulnResult struct {
	Target        string         `json:"target"`
	VulnID        string         `json:"vuln_id"`
	Name          string         `json:"name"`
	Severity      string         `json:"severity"` // critical, high, medium, low, info
	Description   string         `json:"description,omitempty"`
	Evidence      string         `json:"evidence,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	Reference     []string       `json:"reference,omitempty"`
	MatchedAt     string         `json:"matched_at,omitempty"`
	ExtractedInfo map[string]any `json:"extracted_info,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
}

// VulnScanResult represents the overall scan result
type VulnScanResult struct {
	Target       string       `json:"target"`
	TotalChecked int          `json:"total_checked"`
	TotalFound   int          `json:"total_found"`
	StartTime    time.Time    `json:"start_time"`
	EndTime      time.Time    `json:"end_time"`
	Duration     string       `json:"duration"`
	Vulns        []VulnResult `json:"vulns"`
	Summary      VulnSummary  `json:"summary"`
}

// VulnSummary represents vulnerability count by severity
type VulnSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// POCTemplate represents a Nuclei-compatible POC template
type POCTemplate struct {
	ID          string            `yaml:"id" json:"id"`
	Info        POCInfo           `yaml:"info" json:"info"`
	Requests    []POCRequest      `yaml:"requests,omitempty" json:"requests,omitempty"`
	HTTP        []POCRequest      `yaml:"http,omitempty" json:"http,omitempty"`
	Network     []NetworkRequest  `yaml:"network,omitempty" json:"network,omitempty"`
	Variables   map[string]string `yaml:"variables,omitempty" json:"variables,omitempty"`
}

// POCInfo represents POC metadata
type POCInfo struct {
	Name        string   `yaml:"name" json:"name"`
	Author      string   `yaml:"author" json:"author"`
	Severity    string   `yaml:"severity" json:"severity"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Reference   []string `yaml:"reference,omitempty" json:"reference,omitempty"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Remediation string   `yaml:"remediation,omitempty" json:"remediation,omitempty"`
}

// POCRequest represents an HTTP request in POC
type POCRequest struct {
	Method           string            `yaml:"method" json:"method"`
	Path             []string          `yaml:"path" json:"path"`
	Headers          map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body             string            `yaml:"body,omitempty" json:"body,omitempty"`
	Matchers         []Matcher         `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string           `yaml:"matchers-condition,omitempty" json:"matchers_condition,omitempty"`
	Extractors       []Extractor       `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	FollowRedirects  bool              `yaml:"redirects,omitempty" json:"follow_redirects,omitempty"`
	MaxRedirects     int               `yaml:"max-redirects,omitempty" json:"max_redirects,omitempty"`
	Raw              []string          `yaml:"raw,omitempty" json:"raw,omitempty"`
}

// NetworkRequest represents a network (TCP/UDP) request
type NetworkRequest struct {
	Host     string    `yaml:"host" json:"host"`
	Inputs   []Input   `yaml:"inputs" json:"inputs"`
	Matchers []Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	ReadSize int       `yaml:"read-size,omitempty" json:"read_size,omitempty"`
}

// Input represents network input data
type Input struct {
	Data string `yaml:"data" json:"data"`
	Type string `yaml:"type,omitempty" json:"type,omitempty"` // hex, text
	Read int    `yaml:"read,omitempty" json:"read,omitempty"`
}

// Matcher represents a response matcher
type Matcher struct {
	Type      string   `yaml:"type" json:"type"` // word, regex, status, size, binary, dsl
	Words     []string `yaml:"words,omitempty" json:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Status    []int    `yaml:"status,omitempty" json:"status,omitempty"`
	Size      []int    `yaml:"size,omitempty" json:"size,omitempty"`
	Binary    []string `yaml:"binary,omitempty" json:"binary,omitempty"`
	DSL       []string `yaml:"dsl,omitempty" json:"dsl,omitempty"`
	Condition string   `yaml:"condition,omitempty" json:"condition,omitempty"` // and, or
	Part      string   `yaml:"part,omitempty" json:"part,omitempty"`           // body, header, all, response
	Negative  bool     `yaml:"negative,omitempty" json:"negative,omitempty"`
}

// Extractor represents information extractor
type Extractor struct {
	Type  string   `yaml:"type" json:"type"` // regex, kval, json, xpath
	Name  string   `yaml:"name,omitempty" json:"name,omitempty"`
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Group int      `yaml:"group,omitempty" json:"group,omitempty"`
	KVal  []string `yaml:"kval,omitempty" json:"kval,omitempty"`
	Part  string   `yaml:"part,omitempty" json:"part,omitempty"`
}

// VulnScanner handles vulnerability scanning
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
		concurrency = 10
	}

	return &VulnScanner{
		Timeout: 15 * time.Second,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 10 * time.Second,
				}).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
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
				Name:     "环境配置文件泄露",
				Severity: "high",
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
				Name:     "Git配置泄露",
				Severity: "medium",
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
			defer resp.Body.Close()

			// Read response
			respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			if err != nil {
				continue
			}

			// Build response data for matching
			responseData := &ResponseData{
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,
				Body:       string(respBody),
				BodyBytes:  respBody,
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

// ResponseData holds response information for matching
type ResponseData struct {
	StatusCode int
	Headers    http.Header
	Body       string
	BodyBytes  []byte
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

// BruteForceResult represents brute force attack result
type BruteForceResult struct {
	Target    string           `json:"target"`
	Port      int              `json:"port"`
	Service   string           `json:"service"`
	Success   bool             `json:"success"`
	Username  string           `json:"username,omitempty"`
	Password  string           `json:"password,omitempty"`
	Attempts  int              `json:"attempts"`
	Duration  string           `json:"duration"`
	Credentials []Credential   `json:"credentials,omitempty"`
}

// Credential represents a valid credential pair
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// WeakPasswordScanner handles weak password brute force
type WeakPasswordScanner struct {
	Timeout     time.Duration
	Concurrency int
	Usernames   []string
	Passwords   []string
}

// NewWeakPasswordScanner creates a new weak password scanner
func NewWeakPasswordScanner(concurrency int) *WeakPasswordScanner {
	if concurrency <= 0 {
		concurrency = 5
	}

	return &WeakPasswordScanner{
		Timeout:     5 * time.Second,
		Concurrency: concurrency,
		Usernames:   getUsernamesFromConfig(),
		Passwords:   getPasswordsFromConfig(),
	}
}

// getUsernamesFromConfig returns usernames from configuration
func getUsernamesFromConfig() []string {
	creds := config.GetDefaultCredentials()
	if len(creds) > 0 {
		// Extract unique usernames
		seen := make(map[string]bool)
		var usernames []string
		for _, c := range creds {
			if c.Username != "" && !seen[c.Username] {
				seen[c.Username] = true
				usernames = append(usernames, c.Username)
			}
		}
		if len(usernames) > 0 {
			return usernames
		}
	}
	// Minimal fallback
	return []string{"admin", "root", "test", "user"}
}

// getPasswordsFromConfig returns passwords from configuration
func getPasswordsFromConfig() []string {
	passwords := GetWeakPasswords()
	if len(passwords) > 0 {
		return passwords
	}
	// Minimal fallback
	return []string{"admin", "123456", "password", "root", "test"}
}

// BruteForceSSH attempts SSH brute force
func (s *WeakPasswordScanner) BruteForceSSH(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "ssh",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	for _, username := range s.Usernames {
		for _, password := range s.Passwords {
			select {
			case <-ctx.Done():
				result.Attempts = attempts
				result.Duration = time.Since(start).String()
				return result
			default:
			}

			attempts++
			if s.trySSH(host, port, username, password) {
				result.Success = true
				result.Username = username
				result.Password = password
				result.Credentials = append(result.Credentials, Credential{
					Username: username,
					Password: password,
				})
				// Continue to find more
			}
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// trySSH attempts SSH authentication (simplified - would need golang.org/x/crypto/ssh)
func (s *WeakPasswordScanner) trySSH(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Read SSH banner
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return false
	}

	banner := string(buffer[:n])
	if !strings.HasPrefix(banner, "SSH-") {
		return false
	}

	// Note: Full SSH auth would require golang.org/x/crypto/ssh package
	// This is a simplified check - real implementation would use SSH client
	return false
}

// BruteForceMySQL attempts MySQL brute force
func (s *WeakPasswordScanner) BruteForceMySQL(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "mysql",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	// Get MySQL-specific credentials from config
	mysqlCreds := config.GetServiceCredentials("mysql")
	var mysqlUsers []string
	if len(mysqlCreds) > 0 {
		seen := make(map[string]bool)
		for _, c := range mysqlCreds {
			if c.Username != "" && !seen[c.Username] {
				seen[c.Username] = true
				mysqlUsers = append(mysqlUsers, c.Username)
			}
		}
	}
	if len(mysqlUsers) == 0 {
		mysqlUsers = []string{"root", "mysql", "admin"}
	}

	for _, u := range mysqlUsers {
		for _, p := range s.Passwords {
			select {
			case <-ctx.Done():
				result.Attempts = attempts
				result.Duration = time.Since(start).String()
				return result
			default:
			}

			attempts++
			// Note: Real implementation would use database/sql with mysql driver
			// Placeholder - would try connecting with u and p
			_ = u
			_ = p
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// BruteForceFTP attempts FTP brute force
func (s *WeakPasswordScanner) BruteForceFTP(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "ftp",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	for _, username := range s.Usernames {
		for _, password := range s.Passwords {
			select {
			case <-ctx.Done():
				result.Attempts = attempts
				result.Duration = time.Since(start).String()
				return result
			default:
			}

			attempts++
			if s.tryFTP(host, port, username, password) {
				result.Success = true
				result.Username = username
				result.Password = password
				result.Credentials = append(result.Credentials, Credential{
					Username: username,
					Password: password,
				})
			}
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// tryFTP attempts FTP authentication
func (s *WeakPasswordScanner) tryFTP(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read welcome banner
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220") {
		return false
	}

	// Send USER command
	fmt.Fprintf(conn, "USER %s\r\n", username)
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if password needed
	if !strings.HasPrefix(response, "331") {
		return false
	}

	// Send PASS command
	fmt.Fprintf(conn, "PASS %s\r\n", password)
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	response, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if login successful
	if strings.HasPrefix(response, "230") {
		fmt.Fprintf(conn, "QUIT\r\n")
		return true
	}

	return false
}

// BruteForceRedis attempts Redis brute force
func (s *WeakPasswordScanner) BruteForceRedis(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "redis",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	// First try without password
	if s.tryRedis(host, port, "") {
		result.Success = true
		result.Password = "(no password)"
		result.Credentials = append(result.Credentials, Credential{
			Username: "",
			Password: "(no password)",
		})
	}

	for _, password := range s.Passwords {
		select {
		case <-ctx.Done():
			result.Attempts = attempts
			result.Duration = time.Since(start).String()
			return result
		default:
		}

		attempts++
		if s.tryRedis(host, port, password) {
			result.Success = true
			result.Password = password
			result.Credentials = append(result.Credentials, Credential{
				Username: "",
				Password: password,
			})
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// tryRedis attempts Redis authentication
func (s *WeakPasswordScanner) tryRedis(host string, port int, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	if password != "" {
		// Send AUTH command
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		if !strings.HasPrefix(response, "+OK") {
			return false
		}
	}

	// Try INFO command
	fmt.Fprintf(conn, "*1\r\n$4\r\nINFO\r\n")
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if INFO returned data (starts with $ for bulk string)
	if strings.HasPrefix(response, "$") {
		return true
	}

	return false
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
