package vulnscan

import (
	"net/http"
	"time"
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
	ID        string            `yaml:"id" json:"id"`
	Info      POCInfo           `yaml:"info" json:"info"`
	Requests  []POCRequest      `yaml:"requests,omitempty" json:"requests,omitempty"`
	HTTP      []POCRequest      `yaml:"http,omitempty" json:"http,omitempty"`
	Network   []NetworkRequest  `yaml:"network,omitempty" json:"network,omitempty"`
	Variables map[string]string `yaml:"variables,omitempty" json:"variables,omitempty"`
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
	Method            string            `yaml:"method" json:"method"`
	Path              []string          `yaml:"path" json:"path"`
	Headers           map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body              string            `yaml:"body,omitempty" json:"body,omitempty"`
	Matchers          []Matcher         `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty" json:"matchers_condition,omitempty"`
	Extractors        []Extractor       `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	FollowRedirects   bool              `yaml:"redirects,omitempty" json:"follow_redirects,omitempty"`
	MaxRedirects      int               `yaml:"max-redirects,omitempty" json:"max_redirects,omitempty"`
	Raw               []string          `yaml:"raw,omitempty" json:"raw,omitempty"`
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

// ResponseData holds HTTP response data for matching
type ResponseData struct {
	StatusCode int
	Headers    http.Header
	Body       string
}
