package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Engine is the fingerprint detection engine (veo-style)
type Engine struct {
	Rules    map[string]*FingerprintRule
	Config   *EngineConfig
	mu       sync.RWMutex
	compiled map[string]*regexp.Regexp
}

// NewEngine creates a new fingerprint engine
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}
	return &Engine{
		Rules:    make(map[string]*FingerprintRule),
		Config:   config,
		compiled: make(map[string]*regexp.Regexp),
	}
}

// LoadRules loads fingerprint rules from a file or directory
func (e *Engine) LoadRules(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	if info.IsDir() {
		// Load all YAML files from directory
		return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(filePath))
			if ext == ".yaml" || ext == ".yml" {
				if err := e.loadRulesFromFile(filePath); err != nil {
					fmt.Printf("Warning: failed to load rules from %s: %v\n", filePath, err)
				}
			}
			return nil
		})
	}

	return e.loadRulesFromFile(path)
}

// loadRulesFromFile loads rules from a single YAML file
func (e *Engine) loadRulesFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Parse YAML as map
	var rules map[string]*FingerprintRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse YAML %s: %w", filePath, err)
	}

	// Blacklist of overly broad rules that cause false positives
	blacklist := map[string]bool{
		"管理后台登录": true, // Too broad: matches any page with 管理+登录+login
		"资管云":     true, // Contains DXImageTransform which is common IE compat code
		"jeecgboot": true, // Contains polyfill_ which is common in many sites
	}

	// Process each rule
	for name, rule := range rules {
		if rule == nil {
			continue
		}
		// Skip blacklisted rules
		if blacklist[name] {
			continue
		}
		rule.ID = name
		rule.Name = name
		if rule.Condition == "" {
			rule.Condition = "or"
		}
		e.Rules[name] = rule
	}

	return nil
}

// RulesCount returns the number of loaded rules
func (e *Engine) RulesCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.Rules)
}

// AnalyzeResponse analyzes an HTTP response against loaded rules
func (e *Engine) AnalyzeResponse(resp *HTTPResponse) []*FingerprintMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if resp == nil {
		return nil
	}

	matches := make([]*FingerprintMatch, 0)
	seen := make(map[string]bool)

	for _, rule := range e.Rules {
		if match := e.matchRule(resp, rule); match != nil {
			if !seen[rule.Name] {
				seen[rule.Name] = true
				matches = append(matches, match)
			}
		}
	}

	return matches
}

// matchRule checks if a response matches a rule
func (e *Engine) matchRule(resp *HTTPResponse, rule *FingerprintRule) *FingerprintMatch {
	if len(rule.DSL) == 0 {
		return nil
	}

	matchedDSLs := make([]string, 0)
	isAnd := strings.ToLower(rule.Condition) == "and"

	for _, dsl := range rule.DSL {
		matched := e.evaluateDSL(dsl, resp)
		if matched {
			matchedDSLs = append(matchedDSLs, dsl)
			if !isAnd {
				// OR condition: one match is enough
				break
			}
		} else if isAnd {
			// AND condition: all must match
			return nil
		}
	}

	if len(matchedDSLs) == 0 {
		return nil
	}

	// Calculate confidence based on number of matched DSLs
	confidence := 70
	if len(matchedDSLs) >= 2 {
		confidence = 85
	}
	if isAnd && len(matchedDSLs) == len(rule.DSL) {
		confidence = 95
	}

	// Parse tags
	var tags []string
	if rule.Tags != "" {
		tags = strings.Split(rule.Tags, ",")
		for i := range tags {
			tags[i] = strings.TrimSpace(tags[i])
		}
	}

	return &FingerprintMatch{
		URL:        resp.URL,
		RuleName:   rule.Name,
		Technology: rule.Name,
		DSLMatched: matchedDSLs,
		Timestamp:  time.Now(),
		Category:   rule.Category,
		Tags:       tags,
		Confidence: confidence,
		Method:     "passive",
	}
}

// evaluateDSL evaluates a DSL expression against an HTTP response
func (e *Engine) evaluateDSL(dsl string, resp *HTTPResponse) bool {
	dsl = strings.TrimSpace(dsl)

	// Parse DSL function
	if strings.HasPrefix(dsl, "contains(") {
		return e.evalContains(dsl, resp)
	}
	if strings.HasPrefix(dsl, "contains_all(") {
		return e.evalContainsAll(dsl, resp)
	}
	if strings.HasPrefix(dsl, "contains_any(") {
		return e.evalContainsAny(dsl, resp)
	}
	if strings.HasPrefix(dsl, "title(") {
		return e.evalTitle(dsl, resp)
	}
	if strings.HasPrefix(dsl, "icon(") {
		return e.evalIcon(dsl, resp)
	}
	if strings.HasPrefix(dsl, "status(") {
		return e.evalStatus(dsl, resp)
	}
	if strings.HasPrefix(dsl, "regex(") {
		return e.evalRegex(dsl, resp)
	}
	if strings.HasPrefix(dsl, "header(") {
		return e.evalHeader(dsl, resp)
	}

	return false
}

// evalContains evaluates contains(target, value1, value2, ...)
// Returns true if target contains ANY of the values
// target must be: body, header, title, server, url
func (e *Engine) evalContains(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "contains")
	if len(args) < 2 {
		return false
	}

	source := strings.ToLower(strings.Trim(args[0], "'\""))
	var content string

	switch source {
	case "body":
		content = strings.ToLower(resp.Body)
	case "header", "headers":
		content = strings.ToLower(resp.GetAllHeaders())
	case "title":
		content = strings.ToLower(resp.Title)
	case "server":
		content = strings.ToLower(resp.GetHeader("Server"))
	case "url":
		content = strings.ToLower(resp.URL)
	default:
		// Unknown source, return false (strict mode like veo)
		return false
	}

	// Check if any of the patterns match (OR logic)
	for i := 1; i < len(args); i++ {
		pattern := strings.ToLower(strings.Trim(args[i], "'\""))
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// evalContainsAll evaluates contains_all(target, value1, value2, ...)
// Returns true if target contains ALL of the values
// target must be: body, header, title, server, url
func (e *Engine) evalContainsAll(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "contains_all")
	if len(args) < 2 {
		return false
	}

	source := strings.ToLower(strings.Trim(args[0], "'\""))
	var content string

	switch source {
	case "body":
		content = strings.ToLower(resp.Body)
	case "header", "headers":
		content = strings.ToLower(resp.GetAllHeaders())
	case "title":
		content = strings.ToLower(resp.Title)
	case "server":
		content = strings.ToLower(resp.GetHeader("Server"))
	case "url":
		content = strings.ToLower(resp.URL)
	default:
		// Unknown source, return false (strict mode like veo)
		return false
	}

	// Check if ALL patterns match (AND logic)
	for i := 1; i < len(args); i++ {
		pattern := strings.ToLower(strings.Trim(args[i], "'\""))
		if !strings.Contains(content, pattern) {
			return false
		}
	}

	return true
}

// evalContainsAny evaluates contains_any(target, value1, value2, ...)
// Same as contains but explicit
func (e *Engine) evalContainsAny(dsl string, resp *HTTPResponse) bool {
	// Reuse contains logic
	newDSL := "contains" + dsl[len("contains_any"):]
	return e.evalContains(newDSL, resp)
}

// evalTitle evaluates title('value')
func (e *Engine) evalTitle(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "title")
	if len(args) < 1 {
		return false
	}

	titleLower := strings.ToLower(resp.Title)
	patternLower := strings.ToLower(strings.Trim(args[0], "'\""))

	return strings.Contains(titleLower, patternLower)
}

// evalIcon evaluates icon('/path', 'hash') or icon('/path', 'hash1', 'hash2', ...)
func (e *Engine) evalIcon(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "icon")
	if len(args) < 2 {
		return false
	}

	// Skip first arg (path), check hash values
	for i := 1; i < len(args); i++ {
		hash := strings.Trim(args[i], "'\"")
		if resp.IconHash == hash || resp.IconMD5 == hash {
			return true
		}
	}

	return false
}

// evalStatus evaluates status(code)
func (e *Engine) evalStatus(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "status")
	if len(args) < 1 {
		return false
	}

	code, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		return false
	}

	return resp.StatusCode == code
}

// evalRegex evaluates regex(target, pattern)
func (e *Engine) evalRegex(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "regex")
	if len(args) < 2 {
		return false
	}

	target := strings.ToLower(args[0])
	pattern := strings.Trim(args[1], "'\"")

	var content string
	switch target {
	case "body":
		content = resp.Body
	case "header":
		content = resp.GetAllHeaders()
	case "title":
		content = resp.Title
	default:
		content = resp.Body
	}

	// Use cached regex or compile new one
	re, ok := e.compiled[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile("(?i)" + pattern)
		if err != nil {
			return false
		}
		e.compiled[pattern] = re
	}

	return re.MatchString(content)
}

// evalHeader evaluates header(name, value) or header('value') in all headers
func (e *Engine) evalHeader(dsl string, resp *HTTPResponse) bool {
	args := e.parseDSLArgs(dsl, "header")
	if len(args) < 1 {
		return false
	}

	if len(args) == 1 {
		// Check if value exists in any header
		value := strings.ToLower(strings.Trim(args[0], "'\""))
		headerStr := strings.ToLower(resp.GetAllHeaders())
		return strings.Contains(headerStr, value)
	}

	// Check specific header name for value
	headerName := strings.Trim(args[0], "'\"")
	headerValue := strings.ToLower(resp.GetHeader(headerName))
	pattern := strings.ToLower(strings.Trim(args[1], "'\""))

	return strings.Contains(headerValue, pattern)
}

// parseDSLArgs parses arguments from a DSL function call
func (e *Engine) parseDSLArgs(dsl, funcName string) []string {
	// Remove function name and parentheses
	prefix := funcName + "("
	if !strings.HasPrefix(dsl, prefix) {
		return nil
	}

	content := dsl[len(prefix):]
	if idx := strings.LastIndex(content, ")"); idx >= 0 {
		content = content[:idx]
	}

	// Parse arguments, handling quoted strings
	args := make([]string, 0)
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(content); i++ {
		c := content[i]

		if !inQuote && (c == '\'' || c == '"') {
			inQuote = true
			quoteChar = c
			current.WriteByte(c)
		} else if inQuote && c == quoteChar {
			inQuote = false
			quoteChar = 0
			current.WriteByte(c)
		} else if !inQuote && c == ',' {
			arg := strings.TrimSpace(current.String())
			if arg != "" {
				args = append(args, arg)
			}
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}

	// Add last argument
	if current.Len() > 0 {
		arg := strings.TrimSpace(current.String())
		if arg != "" {
			args = append(args, arg)
		}
	}

	return args
}

// GetRule returns a rule by name
func (e *Engine) GetRule(name string) *FingerprintRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Rules[name]
}

// ListRules returns all rule names
func (e *Engine) ListRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.Rules))
	for name := range e.Rules {
		names = append(names, name)
	}
	return names
}

// ListRulesByCategory returns rules filtered by category
func (e *Engine) ListRulesByCategory(category string) []*FingerprintRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*FingerprintRule, 0)
	categoryLower := strings.ToLower(category)

	for _, rule := range e.Rules {
		if strings.ToLower(rule.Category) == categoryLower {
			rules = append(rules, rule)
		}
	}
	return rules
}

// ListCategories returns all unique categories
func (e *Engine) ListCategories() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	categories := make(map[string]bool)
	for _, rule := range e.Rules {
		if rule.Category != "" {
			categories[rule.Category] = true
		}
	}

	result := make([]string, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}
	return result
}
