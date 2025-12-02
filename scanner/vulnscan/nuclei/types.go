package nuclei

import (
	"regexp"
	"time"
)

// NucleiTemplate Nuclei 模板结构
type NucleiTemplate struct {
	ID   string `yaml:"id" json:"id"`
	Info Info   `yaml:"info" json:"info"`

	// 请求类型
	HTTP      []HTTPRequest      `yaml:"http,omitempty" json:"http,omitempty"`
	DNS       []DNSRequest       `yaml:"dns,omitempty" json:"dns,omitempty"`
	TCP       []TCPRequest       `yaml:"tcp,omitempty" json:"tcp,omitempty"`
	Headless  []HeadlessRequest  `yaml:"headless,omitempty" json:"headless,omitempty"`
	Workflows []WorkflowTemplate `yaml:"workflows,omitempty" json:"workflows,omitempty"`

	// 变量
	Variables map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`

	// 原始内容
	RawContent string `yaml:"-" json:"-"`
	FilePath   string `yaml:"-" json:"file_path,omitempty"`
}

// Info 模板信息
type Info struct {
	Name           string            `yaml:"name" json:"name"`
	Author         string            `yaml:"author" json:"author"`
	Severity       Severity          `yaml:"severity" json:"severity"`
	Description    string            `yaml:"description,omitempty" json:"description,omitempty"`
	Reference      []string          `yaml:"reference,omitempty" json:"reference,omitempty"`
	Tags           string            `yaml:"tags,omitempty" json:"tags,omitempty"`
	Classification Classification    `yaml:"classification,omitempty" json:"classification,omitempty"`
	Metadata       map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	Remediation    string            `yaml:"remediation,omitempty" json:"remediation,omitempty"`
}

// Severity 严重程度
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// Classification 漏洞分类
type Classification struct {
	CVEID       string  `yaml:"cve-id,omitempty" json:"cve_id,omitempty"`
	CWEID       string  `yaml:"cwe-id,omitempty" json:"cwe_id,omitempty"`
	CVSSMetrics string  `yaml:"cvss-metrics,omitempty" json:"cvss_metrics,omitempty"`
	CVSSScore   float64 `yaml:"cvss-score,omitempty" json:"cvss_score,omitempty"`
}

// HTTPRequest HTTP 请求模板
type HTTPRequest struct {
	// 请求定义
	Method           string              `yaml:"method,omitempty" json:"method,omitempty"`
	Path             []string            `yaml:"path,omitempty" json:"path,omitempty"`
	Raw              []string            `yaml:"raw,omitempty" json:"raw,omitempty"`
	Body             string              `yaml:"body,omitempty" json:"body,omitempty"`
	Headers          map[string]string   `yaml:"headers,omitempty" json:"headers,omitempty"`
	
	// 请求选项
	Redirects        bool                `yaml:"redirects,omitempty" json:"redirects,omitempty"`
	MaxRedirects     int                 `yaml:"max-redirects,omitempty" json:"max_redirects,omitempty"`
	HostRedirects    bool                `yaml:"host-redirects,omitempty" json:"host_redirects,omitempty"`
	Unsafe           bool                `yaml:"unsafe,omitempty" json:"unsafe,omitempty"`
	ReadAll          bool                `yaml:"read-all,omitempty" json:"read_all,omitempty"`
	
	// 匹配器和提取器
	Matchers         []Matcher           `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string             `yaml:"matchers-condition,omitempty" json:"matchers_condition,omitempty"`
	Extractors       []Extractor         `yaml:"extractors,omitempty" json:"extractors,omitempty"`
	
	// 攻击模式
	Attack           string              `yaml:"attack,omitempty" json:"attack,omitempty"`
	Payloads         map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty"`
	
	// 请求控制
	StopAtFirstMatch bool                `yaml:"stop-at-first-match,omitempty" json:"stop_at_first_match,omitempty"`
	SkipVariables    bool                `yaml:"skip-variables-check,omitempty" json:"skip_variables_check,omitempty"`
	
	// 请求关联
	CookieReuse      bool                `yaml:"cookie-reuse,omitempty" json:"cookie_reuse,omitempty"`
	ReqCondition     bool                `yaml:"req-condition,omitempty" json:"req_condition,omitempty"`
}

// DNSRequest DNS 请求模板
type DNSRequest struct {
	Name              string    `yaml:"name" json:"name"`
	Type              string    `yaml:"type" json:"type"`
	Class             string    `yaml:"class,omitempty" json:"class,omitempty"`
	Recursion         bool      `yaml:"recursion,omitempty" json:"recursion,omitempty"`
	Retries           int       `yaml:"retries,omitempty" json:"retries,omitempty"`
	Matchers          []Matcher `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string    `yaml:"matchers-condition,omitempty" json:"matchers_condition,omitempty"`
	Extractors        []Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// TCPRequest TCP 请求模板
type TCPRequest struct {
	Inputs            []TCPInput  `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Host              []string    `yaml:"host,omitempty" json:"host,omitempty"`
	ReadSize          int         `yaml:"read-size,omitempty" json:"read_size,omitempty"`
	Matchers          []Matcher   `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string      `yaml:"matchers-condition,omitempty" json:"matchers_condition,omitempty"`
	Extractors        []Extractor `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// TCPInput TCP 输入
type TCPInput struct {
	Data string `yaml:"data,omitempty" json:"data,omitempty"`
	Type string `yaml:"type,omitempty" json:"type,omitempty"` // hex or text
	Read int    `yaml:"read,omitempty" json:"read,omitempty"`
}

// HeadlessRequest Headless 请求模板
type HeadlessRequest struct {
	Steps             []HeadlessStep `yaml:"steps,omitempty" json:"steps,omitempty"`
	Matchers          []Matcher      `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	MatchersCondition string         `yaml:"matchers-condition,omitempty" json:"matchers_condition,omitempty"`
	Extractors        []Extractor    `yaml:"extractors,omitempty" json:"extractors,omitempty"`
}

// HeadlessStep Headless 步骤
type HeadlessStep struct {
	Action string            `yaml:"action" json:"action"`
	Args   map[string]string `yaml:"args,omitempty" json:"args,omitempty"`
}

// WorkflowTemplate 工作流模板
type WorkflowTemplate struct {
	Template  string   `yaml:"template,omitempty" json:"template,omitempty"`
	Tags      string   `yaml:"tags,omitempty" json:"tags,omitempty"`
	Matchers  []string `yaml:"matchers,omitempty" json:"matchers,omitempty"`
	Subtemplates []SubTemplate `yaml:"subtemplates,omitempty" json:"subtemplates,omitempty"`
}

// SubTemplate 子模板
type SubTemplate struct {
	Template string `yaml:"template" json:"template"`
	Tags     string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Matcher 匹配器
type Matcher struct {
	Type      string   `yaml:"type" json:"type"`
	Part      string   `yaml:"part,omitempty" json:"part,omitempty"`
	Words     []string `yaml:"words,omitempty" json:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Binary    []string `yaml:"binary,omitempty" json:"binary,omitempty"`
	Status    []int    `yaml:"status,omitempty" json:"status,omitempty"`
	Size      []int    `yaml:"size,omitempty" json:"size,omitempty"`
	DSL       []string `yaml:"dsl,omitempty" json:"dsl,omitempty"`
	XPath     []string `yaml:"xpath,omitempty" json:"xpath,omitempty"`
	Condition string   `yaml:"condition,omitempty" json:"condition,omitempty"` // and, or
	Negative  bool     `yaml:"negative,omitempty" json:"negative,omitempty"`
	Internal  bool     `yaml:"internal,omitempty" json:"internal,omitempty"`
	Name      string   `yaml:"name,omitempty" json:"name,omitempty"`
	
	// 编译后的正则
	CompiledRegex []*regexp.Regexp `yaml:"-" json:"-"`
}

// Extractor 提取器
type Extractor struct {
	Type     string   `yaml:"type" json:"type"`
	Part     string   `yaml:"part,omitempty" json:"part,omitempty"`
	Name     string   `yaml:"name,omitempty" json:"name,omitempty"`
	Regex    []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	Group    int      `yaml:"group,omitempty" json:"group,omitempty"`
	KVal     []string `yaml:"kval,omitempty" json:"kval,omitempty"`
	JSON     []string `yaml:"json,omitempty" json:"json,omitempty"`
	XPath    []string `yaml:"xpath,omitempty" json:"xpath,omitempty"`
	Attribute string  `yaml:"attribute,omitempty" json:"attribute,omitempty"`
	DSL      []string `yaml:"dsl,omitempty" json:"dsl,omitempty"`
	Internal bool     `yaml:"internal,omitempty" json:"internal,omitempty"`
	
	// 编译后的正则
	CompiledRegex []*regexp.Regexp `yaml:"-" json:"-"`
}

// ScanResult 扫描结果
type ScanResult struct {
	TemplateID    string                 `json:"template_id"`
	TemplateName  string                 `json:"template_name"`
	Severity      Severity               `json:"severity"`
	Host          string                 `json:"host"`
	Matched       bool                   `json:"matched"`
	MatchedAt     string                 `json:"matched_at,omitempty"`
	ExtractedData map[string]interface{} `json:"extracted_data,omitempty"`
	Request       string                 `json:"request,omitempty"`
	Response      string                 `json:"response,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Error         string                 `json:"error,omitempty"`
	
	// 额外信息
	CVEID         string                 `json:"cve_id,omitempty"`
	Description   string                 `json:"description,omitempty"`
	Reference     []string               `json:"reference,omitempty"`
	Tags          string                 `json:"tags,omitempty"`
}

// ExecutorOptions 执行器选项
type ExecutorOptions struct {
	Timeout          time.Duration
	MaxRedirects     int
	FollowRedirects  bool
	Concurrency      int
	RateLimit        int
	Headers          map[string]string
	Proxy            string
	DisableKeepAlive bool
	Debug            bool
}

// DefaultExecutorOptions 默认执行器选项
func DefaultExecutorOptions() *ExecutorOptions {
	return &ExecutorOptions{
		Timeout:         10 * time.Second,
		MaxRedirects:    10,
		FollowRedirects: true,
		Concurrency:     25,
		RateLimit:       150,
	}
}
