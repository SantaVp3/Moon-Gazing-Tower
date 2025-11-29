package fingerprint

import (
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// StringList is a custom type that can be a single string or a list of strings in YAML
type StringList []string

// UnmarshalYAML implements custom YAML unmarshaling
func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// Single string value
		*s = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		// List of strings
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		*s = list
		return nil
	}
	return nil
}

// FingerprintRule represents a fingerprint rule from veo-style YAML
type FingerprintRule struct {
	ID        string     `yaml:"-"`        // Rule ID (from map key)
	Name      string     `yaml:"-"`        // Rule name (same as ID)
	DSL       StringList `yaml:"dsl"`      // DSL expressions for matching
	Condition string     `yaml:"condition"` // "and" or "or", default is "or"
	Category  string     `yaml:"category"`  // Technology category
	Tags      string     `yaml:"tags"`      // Comma-separated tags
	Path      StringList `yaml:"path"`      // Paths for active probing
	Header    string     `yaml:"header"`    // Custom headers for requests
}

// FingerprintMatch represents a successful fingerprint match
type FingerprintMatch struct {
	URL        string    `json:"url"`
	RuleName   string    `json:"rule_name"`
	Technology string    `json:"technology"`
	DSLMatched []string  `json:"dsl_matched,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	Snippet    string    `json:"snippet,omitempty"`
	Category   string    `json:"category,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	Confidence int       `json:"confidence"`
	Method     string    `json:"method"` // passive, active, icon
}

// HTTPResponse represents an HTTP response for fingerprint analysis
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	Title      string
	URL        string
	IconHash   string // mmh3 hash of favicon
	IconMD5    string // MD5 of favicon
}

// GetHeader returns a header value (case-insensitive)
func (r *HTTPResponse) GetHeader(key string) string {
	key = strings.ToLower(key)
	for k, v := range r.Headers {
		if strings.ToLower(k) == key {
			return v
		}
	}
	return ""
}

// GetAllHeaders returns all headers as a single string
func (r *HTTPResponse) GetAllHeaders() string {
	var sb strings.Builder
	for k, v := range r.Headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\n")
	}
	return sb.String()
}

// EngineConfig represents the fingerprint engine configuration
type EngineConfig struct {
	RulesPath     string // Path to rules directory or file
	Concurrency   int    // Number of concurrent scans
	Timeout       int    // HTTP timeout in seconds
	EnableActive  bool   // Enable active probing (path-based)
	EnablePassive bool   // Enable passive detection
	EnableIcon    bool   // Enable icon hash detection
}

// DefaultEngineConfig returns default engine configuration
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		Concurrency:   20,
		Timeout:       10,
		EnableActive:  true,
		EnablePassive: true,
		EnableIcon:    true,
	}
}
