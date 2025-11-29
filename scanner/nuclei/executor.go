package nuclei

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Executor Nuclei 模板执行器
type Executor struct {
	loader  *TemplateLoader
	client  *http.Client
	options *ExecutorOptions
	
	// 变量存储
	variables map[string]interface{}
	varMu     sync.RWMutex
}

// NewExecutor 创建执行器
func NewExecutor(loader *TemplateLoader, options *ExecutorOptions) *Executor {
	if options == nil {
		options = DefaultExecutorOptions()
	}
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		DisableKeepAlives:   options.DisableKeepAlive,
	}
	
	if options.Proxy != "" {
		proxyURL, _ := url.Parse(options.Proxy)
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
	}
	
	if !options.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	
	return &Executor{
		loader:    loader,
		client:    client,
		options:   options,
		variables: make(map[string]interface{}),
	}
}

// Execute 执行单个模板
func (e *Executor) Execute(ctx context.Context, template *NucleiTemplate, target string) (*ScanResult, error) {
	result := &ScanResult{
		TemplateID:   template.ID,
		TemplateName: template.Info.Name,
		Severity:     template.Info.Severity,
		Host:         target,
		Timestamp:    time.Now(),
		CVEID:        template.Info.Classification.CVEID,
		Description:  template.Info.Description,
		Reference:    template.Info.Reference,
		Tags:         template.Info.Tags,
	}
	
	// 初始化变量
	e.initVariables(template, target)
	
	// 执行 HTTP 请求
	if len(template.HTTP) > 0 {
		matched, err := e.executeHTTP(ctx, template, target, result)
		if err != nil {
			result.Error = err.Error()
			return result, nil
		}
		result.Matched = matched
	}
	
	// TODO: 执行 DNS、TCP、Headless 请求
	
	return result, nil
}

// ExecuteAll 执行所有模板
func (e *Executor) ExecuteAll(ctx context.Context, target string) ([]*ScanResult, error) {
	templates := e.loader.GetTemplates()
	return e.ExecuteTemplates(ctx, templates, target)
}

// ExecuteTemplates 执行指定模板列表
func (e *Executor) ExecuteTemplates(ctx context.Context, templates []*NucleiTemplate, target string) ([]*ScanResult, error) {
	results := make([]*ScanResult, 0)
	resultsMu := sync.Mutex{}
	
	// 使用 semaphore 控制并发
	sem := make(chan struct{}, e.options.Concurrency)
	var wg sync.WaitGroup
	
	for _, template := range templates {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}
		
		wg.Add(1)
		go func(t *NucleiTemplate) {
			defer wg.Done()
			defer func() { <-sem }()
			
			result, err := e.Execute(ctx, t, target)
			if err != nil {
				return
			}
			
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}(template)
	}
	
	wg.Wait()
	return results, nil
}

// ExecuteByTags 根据标签执行模板
func (e *Executor) ExecuteByTags(ctx context.Context, target string, tags ...string) ([]*ScanResult, error) {
	templates := e.loader.GetTemplatesByTags(tags...)
	return e.ExecuteTemplates(ctx, templates, target)
}

// ExecuteBySeverity 根据严重程度执行模板
func (e *Executor) ExecuteBySeverity(ctx context.Context, target string, severity Severity) ([]*ScanResult, error) {
	templates := e.loader.GetTemplatesBySeverity(severity)
	return e.ExecuteTemplates(ctx, templates, target)
}

// initVariables 初始化变量
func (e *Executor) initVariables(template *NucleiTemplate, target string) {
	e.varMu.Lock()
	defer e.varMu.Unlock()
	
	e.variables = make(map[string]interface{})
	
	// 解析目标 URL
	parsedURL, _ := url.Parse(target)
	if parsedURL != nil {
		e.variables["BaseURL"] = target
		e.variables["RootURL"] = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		e.variables["Hostname"] = parsedURL.Hostname()
		e.variables["Host"] = parsedURL.Host
		e.variables["Port"] = parsedURL.Port()
		e.variables["Path"] = parsedURL.Path
		e.variables["Scheme"] = parsedURL.Scheme
	}
	
	// 复制模板变量
	for k, v := range template.Variables {
		e.variables[k] = v
	}
}

// executeHTTP 执行 HTTP 请求
func (e *Executor) executeHTTP(ctx context.Context, template *NucleiTemplate, target string, result *ScanResult) (bool, error) {
	for _, httpReq := range template.HTTP {
		matched, err := e.executeSingleHTTP(ctx, &httpReq, target, result)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// executeSingleHTTP 执行单个 HTTP 请求
func (e *Executor) executeSingleHTTP(ctx context.Context, httpReq *HTTPRequest, target string, result *ScanResult) (bool, error) {
	// 处理 raw 请求
	if len(httpReq.Raw) > 0 {
		return e.executeRawHTTP(ctx, httpReq, target, result)
	}
	
	// 处理路径请求
	if len(httpReq.Path) > 0 {
		return e.executePathHTTP(ctx, httpReq, target, result)
	}
	
	return false, nil
}

// executeRawHTTP 执行原始 HTTP 请求
func (e *Executor) executeRawHTTP(ctx context.Context, httpReq *HTTPRequest, target string, result *ScanResult) (bool, error) {
	for _, raw := range httpReq.Raw {
		// 替换变量
		raw = e.replaceVariables(raw)
		
		// 解析原始请求
		req, err := e.parseRawRequest(ctx, raw, target)
		if err != nil {
			continue
		}
		
		// 发送请求
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// 读取响应
		body, _ := io.ReadAll(resp.Body)
		
		// 检查匹配
		matched := e.checkMatchers(httpReq.Matchers, httpReq.MatchersCondition, resp, body)
		if matched {
			result.MatchedAt = req.URL.String()
			result.Request = raw
			result.Response = string(body)
			
			// 提取数据
			result.ExtractedData = e.extractData(httpReq.Extractors, resp, body)
			
			return true, nil
		}
	}
	
	return false, nil
}

// executePathHTTP 执行路径 HTTP 请求
func (e *Executor) executePathHTTP(ctx context.Context, httpReq *HTTPRequest, target string, result *ScanResult) (bool, error) {
	baseURL, _ := url.Parse(target)
	
	for _, path := range httpReq.Path {
		// 替换变量
		path = e.replaceVariables(path)
		
		// 构建完整 URL
		fullURL := target
		if strings.HasPrefix(path, "/") {
			fullURL = fmt.Sprintf("%s://%s%s", baseURL.Scheme, baseURL.Host, path)
		} else if !strings.HasPrefix(path, "http") {
			fullURL = target + "/" + path
		} else {
			fullURL = path
		}
		
		// 创建请求
		method := httpReq.Method
		if method == "" {
			method = "GET"
		}
		
		var bodyReader io.Reader
		if httpReq.Body != "" {
			bodyReader = strings.NewReader(e.replaceVariables(httpReq.Body))
		}
		
		req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			continue
		}
		
		// 设置 Headers
		for k, v := range httpReq.Headers {
			req.Header.Set(k, e.replaceVariables(v))
		}
		
		// 添加自定义 Headers
		for k, v := range e.options.Headers {
			req.Header.Set(k, v)
		}
		
		// 发送请求
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// 读取响应
		body, _ := io.ReadAll(resp.Body)
		
		// 检查匹配
		matched := e.checkMatchers(httpReq.Matchers, httpReq.MatchersCondition, resp, body)
		if matched {
			result.MatchedAt = fullURL
			result.Response = string(body)
			
			// 提取数据
			result.ExtractedData = e.extractData(httpReq.Extractors, resp, body)
			
			return true, nil
		}
		
		// 如果设置了 stop-at-first-match
		if httpReq.StopAtFirstMatch {
			break
		}
	}
	
	return false, nil
}

// parseRawRequest 解析原始 HTTP 请求
func (e *Executor) parseRawRequest(ctx context.Context, raw string, target string) (*http.Request, error) {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty raw request")
	}
	
	// 解析请求行
	requestLine := strings.TrimSpace(lines[0])
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line")
	}
	
	method := parts[0]
	path := parts[1]
	
	// 构建 URL
	baseURL, _ := url.Parse(target)
	fullURL := fmt.Sprintf("%s://%s%s", baseURL.Scheme, baseURL.Host, path)
	
	// 查找 body
	var bodyStart int
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			bodyStart = i + 1
			break
		}
	}
	
	var body string
	if bodyStart > 0 && bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}
	
	// 创建请求
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	
	// 解析 Headers
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			break
		}
		
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			
			// 跳过 Host header
			if strings.ToLower(key) != "host" {
				req.Header.Set(key, value)
			}
		}
	}
	
	return req, nil
}

// checkMatchers 检查匹配器
func (e *Executor) checkMatchers(matchers []Matcher, condition string, resp *http.Response, body []byte) bool {
	if len(matchers) == 0 {
		return false
	}
	
	results := make([]bool, len(matchers))
	
	for i, matcher := range matchers {
		// 跳过 internal 匹配器
		if matcher.Internal {
			results[i] = true
			continue
		}
		
		results[i] = e.checkMatcher(&matcher, resp, body)
		
		// 处理 negative
		if matcher.Negative {
			results[i] = !results[i]
		}
	}
	
	// 根据条件组合结果
	if condition == "or" {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}
	
	// 默认 and
	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

// checkMatcher 检查单个匹配器
func (e *Executor) checkMatcher(matcher *Matcher, resp *http.Response, body []byte) bool {
	// 获取要匹配的内容
	var content string
	switch matcher.Part {
	case "header":
		var headers bytes.Buffer
		for k, v := range resp.Header {
			headers.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		content = headers.String()
	case "body":
		content = string(body)
	default:
		// 默认匹配整个响应
		var headers bytes.Buffer
		for k, v := range resp.Header {
			headers.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		content = headers.String() + "\n" + string(body)
	}
	
	switch matcher.Type {
	case "status":
		return e.matchStatus(matcher, resp.StatusCode)
	case "size":
		return e.matchSize(matcher, len(body))
	case "word", "words":
		return e.matchWords(matcher, content)
	case "regex":
		return e.matchRegex(matcher, content)
	case "binary":
		return e.matchBinary(matcher, body)
	case "dsl":
		return e.matchDSL(matcher, resp, body)
	}
	
	return false
}

// matchStatus 匹配状态码
func (e *Executor) matchStatus(matcher *Matcher, statusCode int) bool {
	for _, status := range matcher.Status {
		if status == statusCode {
			return true
		}
	}
	return false
}

// matchSize 匹配大小
func (e *Executor) matchSize(matcher *Matcher, size int) bool {
	for _, s := range matcher.Size {
		if s == size {
			return true
		}
	}
	return false
}

// matchWords 匹配关键词
func (e *Executor) matchWords(matcher *Matcher, content string) bool {
	condition := matcher.Condition
	if condition == "" {
		condition = "and"
	}
	
	if condition == "or" {
		for _, word := range matcher.Words {
			if strings.Contains(content, word) {
				return true
			}
		}
		return false
	}
	
	// and 条件
	for _, word := range matcher.Words {
		if !strings.Contains(content, word) {
			return false
		}
	}
	return len(matcher.Words) > 0
}

// matchRegex 匹配正则
func (e *Executor) matchRegex(matcher *Matcher, content string) bool {
	condition := matcher.Condition
	if condition == "" {
		condition = "and"
	}
	
	// 使用编译好的正则
	if len(matcher.CompiledRegex) > 0 {
		if condition == "or" {
			for _, re := range matcher.CompiledRegex {
				if re.MatchString(content) {
					return true
				}
			}
			return false
		}
		
		// and 条件
		for _, re := range matcher.CompiledRegex {
			if !re.MatchString(content) {
				return false
			}
		}
		return len(matcher.CompiledRegex) > 0
	}
	
	// 如果没有编译，动态匹配
	if condition == "or" {
		for _, pattern := range matcher.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(content) {
				return true
			}
		}
		return false
	}
	
	for _, pattern := range matcher.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		if !re.MatchString(content) {
			return false
		}
	}
	return len(matcher.Regex) > 0
}

// matchBinary 匹配二进制
func (e *Executor) matchBinary(matcher *Matcher, body []byte) bool {
	for _, hex := range matcher.Binary {
		decoded, err := hexDecode(hex)
		if err != nil {
			continue
		}
		if bytes.Contains(body, decoded) {
			return true
		}
	}
	return false
}

// matchDSL 匹配 DSL 表达式
func (e *Executor) matchDSL(matcher *Matcher, resp *http.Response, body []byte) bool {
	for _, expr := range matcher.DSL {
		if e.evaluateDSL(expr, resp, body) {
			return true
		}
	}
	return false
}

// evaluateDSL 计算 DSL 表达式
func (e *Executor) evaluateDSL(expr string, resp *http.Response, body []byte) bool {
	// 简单 DSL 实现
	// 支持: status_code == 200, contains(body, "xxx"), len(body) > 100
	
	// 替换变量
	expr = strings.ReplaceAll(expr, "status_code", strconv.Itoa(resp.StatusCode))
	expr = strings.ReplaceAll(expr, "content_length", strconv.Itoa(len(body)))
	
	// contains 函数
	containsRe := regexp.MustCompile(`contains\s*\(\s*body\s*,\s*"([^"]+)"\s*\)`)
	matches := containsRe.FindAllStringSubmatch(expr, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result := strings.Contains(string(body), match[1])
			expr = strings.Replace(expr, match[0], strconv.FormatBool(result), 1)
		}
	}
	
	// 简单数值比较
	if strings.Contains(expr, "==") {
		parts := strings.Split(expr, "==")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			return left == right
		}
	}
	
	if strings.Contains(expr, "true") {
		return true
	}
	
	return false
}

// extractData 提取数据
func (e *Executor) extractData(extractors []Extractor, resp *http.Response, body []byte) map[string]interface{} {
	data := make(map[string]interface{})
	
	for _, extractor := range extractors {
		if extractor.Internal {
			continue
		}
		
		var content string
		switch extractor.Part {
		case "header":
			var headers bytes.Buffer
			for k, v := range resp.Header {
				headers.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
			}
			content = headers.String()
		default:
			content = string(body)
		}
		
		name := extractor.Name
		if name == "" {
			name = extractor.Type
		}
		
		switch extractor.Type {
		case "regex":
			extracted := e.extractRegex(&extractor, content)
			if len(extracted) > 0 {
				data[name] = extracted
			}
		case "kval":
			extracted := e.extractKVal(&extractor, resp)
			if len(extracted) > 0 {
				data[name] = extracted
			}
		case "json":
			extracted := e.extractJSON(&extractor, body)
			if extracted != nil {
				data[name] = extracted
			}
		}
	}
	
	return data
}

// extractRegex 正则提取
func (e *Executor) extractRegex(extractor *Extractor, content string) []string {
	results := make([]string, 0)
	
	regexes := extractor.CompiledRegex
	if len(regexes) == 0 {
		// 动态编译
		for _, pattern := range extractor.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			regexes = append(regexes, re)
		}
	}
	
	for _, re := range regexes {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if extractor.Group > 0 && extractor.Group < len(match) {
				results = append(results, match[extractor.Group])
			} else if len(match) > 1 {
				results = append(results, match[1])
			} else if len(match) > 0 {
				results = append(results, match[0])
			}
		}
	}
	
	return results
}

// extractKVal 键值提取
func (e *Executor) extractKVal(extractor *Extractor, resp *http.Response) map[string]string {
	results := make(map[string]string)
	
	for _, key := range extractor.KVal {
		if values := resp.Header.Values(key); len(values) > 0 {
			results[key] = strings.Join(values, ", ")
		}
	}
	
	return results
}

// extractJSON JSON 提取
func (e *Executor) extractJSON(extractor *Extractor, body []byte) interface{} {
	// 简单实现，后续可以使用 gjson
	return nil
}

// replaceVariables 替换变量
func (e *Executor) replaceVariables(s string) string {
	e.varMu.RLock()
	defer e.varMu.RUnlock()
	
	for k, v := range e.variables {
		placeholder := "{{" + k + "}}"
		s = strings.ReplaceAll(s, placeholder, fmt.Sprintf("%v", v))
	}
	
	return s
}

// hexDecode 十六进制解码
func hexDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string")
	}
	
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		result[i/2] = byte(b)
	}
	
	return result, nil
}
