package core

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// FilterConfig 过滤器配置
type FilterConfig struct {
	ValidStatusCodes     []int  // 有效状态码列表
	InvalidPageThreshold int    // 无效页面阈值（主要筛选）
	SecondaryThreshold   int    // 二次筛选阈值
	EnableStatusFilter   bool   // 是否启用状态码过滤
	FilterTolerance      int64  // 相似页面过滤容错阈值（字节）
}

// DefaultFilterConfig 获取默认过滤器配置
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		ValidStatusCodes:     []int{200, 403, 500, 302, 301, 405},
		InvalidPageThreshold: 3,
		SecondaryThreshold:   1,
		EnableStatusFilter:   true,
		FilterTolerance:      50, // 默认50字节容错
	}
}

// PageHash 页面哈希统计
type PageHash struct {
	Hash          string
	Count         int
	StatusCode    int
	Title         string
	ContentLength int64
	ContentType   string
}

// FilterResult 过滤结果
type FilterResult struct {
	ValidPages     []*DirEntry // 有效页面
	FilteredCount  int         // 被过滤的页面数
	TotalProcessed int         // 总处理数
}

// ResponseFilter 响应过滤器
type ResponseFilter struct {
	config      *FilterConfig
	hashFilter  *HashFilter
	mu          sync.RWMutex
}

// NewResponseFilter 创建响应过滤器
func NewResponseFilter(config *FilterConfig) *ResponseFilter {
	if config == nil {
		config = DefaultFilterConfig()
	}

	return &ResponseFilter{
		config:     config,
		hashFilter: NewHashFilter(config.InvalidPageThreshold, config.FilterTolerance),
	}
}

// IsValidStatusCode 检查状态码是否有效
func (rf *ResponseFilter) IsValidStatusCode(statusCode int) bool {
	if !rf.config.EnableStatusFilter {
		return true
	}
	for _, code := range rf.config.ValidStatusCodes {
		if statusCode == code {
			return true
		}
	}
	return false
}

// ShouldFilter 判断页面是否应该被过滤（去重）
// 返回 true 表示页面应该被过滤掉（是重复/无效页面）
func (rf *ResponseFilter) ShouldFilter(entry *DirEntry) bool {
	if entry == nil {
		return true
	}

	rf.mu.Lock()
	defer rf.mu.Unlock()

	return rf.hashFilter.IsInvalidPage(entry)
}

// Reset 重置过滤器状态
func (rf *ResponseFilter) Reset() {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.hashFilter.Reset()
}

// GetStats 获取过滤统计
func (rf *ResponseFilter) GetStats() map[string]int {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	return map[string]int{
		"unique_hashes": rf.hashFilter.GetPageHashCount(),
	}
}

// HashFilter 哈希过滤器
type HashFilter struct {
	pageHashMap map[string]*PageHash
	threshold   int
	tolerance   int64
	mu          sync.RWMutex
}

// NewHashFilter 创建哈希过滤器
func NewHashFilter(threshold int, tolerance int64) *HashFilter {
	if threshold <= 0 {
		threshold = 3
	}
	if tolerance < 0 {
		tolerance = 50
	}

	return &HashFilter{
		pageHashMap: make(map[string]*PageHash),
		threshold:   threshold,
		tolerance:   tolerance,
	}
}

// IsInvalidPage 判断页面是否为无效页面（重复页面）
func (hf *HashFilter) IsInvalidPage(entry *DirEntry) bool {
	hash := hf.generatePageHash(entry)

	hf.mu.Lock()
	defer hf.mu.Unlock()

	if pageHash, exists := hf.pageHashMap[hash]; exists {
		pageHash.Count++
		return pageHash.Count > hf.threshold
	}

	// 首次出现，记录
	hf.pageHashMap[hash] = &PageHash{
		Hash:          hash,
		Count:         1,
		StatusCode:    entry.StatusCode,
		Title:         entry.Title,
		ContentLength: entry.ContentLength,
		ContentType:   entry.ContentType,
	}
	return false
}

// generatePageHash 生成页面哈希（状态码+标题+容错ContentLength）
func (hf *HashFilter) generatePageHash(entry *DirEntry) string {
	// 计算容错的ContentLength
	tolerantLength := hf.calculateTolerantContentLength(entry.ContentLength)

	// 组合状态码、标题和容错ContentLength生成哈希
	hashSource := fmt.Sprintf("%d|%s|%d",
		entry.StatusCode,
		strings.TrimSpace(entry.Title),
		tolerantLength)

	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashSource)))
	return hash
}

// calculateTolerantContentLength 计算容错的ContentLength
// 基于量级的动态容错机制，解决 Soft 404 页面因反射参数导致长度差异的问题
func (hf *HashFilter) calculateTolerantContentLength(originalLength int64) int64 {
	if hf.tolerance == 0 {
		return originalLength // 禁用容错
	}

	var step int64
	if originalLength < 1000 {
		// 小文件：使用配置的tolerance
		step = hf.tolerance
		if step > 50 {
			step = 50
		}
	} else if originalLength < 5000 {
		// 1k-5k：容错500
		step = 500
	} else if originalLength < 10000 {
		// 5k-10k：容错1000
		step = 1000
	} else {
		// >10k：容错2000
		step = 2000
	}

	if step < hf.tolerance {
		step = hf.tolerance
	}

	// 使用四舍五入进行分桶
	tolerantLength := ((originalLength + step/2) / step) * step
	return tolerantLength
}

// Reset 重置哈希过滤器
func (hf *HashFilter) Reset() {
	hf.mu.Lock()
	defer hf.mu.Unlock()
	hf.pageHashMap = make(map[string]*PageHash)
}

// GetPageHashCount 获取唯一哈希数量
func (hf *HashFilter) GetPageHashCount() int {
	hf.mu.RLock()
	defer hf.mu.RUnlock()
	return len(hf.pageHashMap)
}

// GetInvalidPageHashes 获取被判定为无效的页面哈希
func (hf *HashFilter) GetInvalidPageHashes() []*PageHash {
	hf.mu.RLock()
	defer hf.mu.RUnlock()

	var invalidHashes []*PageHash
	for _, ph := range hf.pageHashMap {
		if ph.Count > hf.threshold {
			invalidHashes = append(invalidHashes, ph)
		}
	}
	return invalidHashes
}

// =====================================================
// 客户端重定向检测
// =====================================================

// DetectClientRedirectURL 检测 HTML/JS 中的客户端重定向 URL
func DetectClientRedirectURL(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}

	// 检测 meta refresh 重定向
	// 标准格式: <meta http-equiv="refresh" content="0;url=http://example.com">
	metaPatterns := []*regexp.Regexp{
		// 标准顺序
		regexp.MustCompile(`(?is)<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`),
		// 属性顺序交换 (content 在前)
		regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)['"][^>]*http-equiv\s*=\s*['"]?refresh['"]?`),
		// 宽松匹配
		regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`),
	}

	for _, re := range metaPatterns {
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return strings.TrimSpace(m[1])
		}
	}

	// 检测 JavaScript 重定向
	jsPatterns := []*regexp.Regexp{
		// location = "..."
		regexp.MustCompile(`(?is)(?:window\.|self\.|top\.|parent\.|)location(?:\.href)?\s*=\s*['"]([^'"]+)['"]`),
		// location.replace("...")
		regexp.MustCompile(`(?is)(?:window\.|self\.|top\.|parent\.|)location\.replace\(\s*['"]([^'"]+)['"]\s*\)`),
		// location.assign("...")
		regexp.MustCompile(`(?is)(?:window\.|self\.|top\.|parent\.|)location\.assign\(\s*['"]([^'"]+)['"]\s*\)`),
	}

	for _, re := range jsPatterns {
		if m := re.FindStringSubmatch(body); len(m) >= 2 {
			return strings.TrimSpace(m[1])
		}
	}

	return ""
}

// ResolveRedirectURL 将相对/协议相对 URL 解析为绝对地址
func ResolveRedirectURL(baseURL, ref string) string {
	ref = strings.TrimSpace(ref)
	if baseURL == "" || ref == "" {
		return ""
	}

	// 如果已经是绝对地址，直接返回
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}

	// 解析 base URL
	base, err := parseURL(baseURL)
	if err != nil {
		return ""
	}

	// 处理协议相对 URL (//example.com)
	if strings.HasPrefix(ref, "//") {
		return base.Scheme + ":" + ref
	}

	// 处理绝对路径 (/path)
	if strings.HasPrefix(ref, "/") {
		return fmt.Sprintf("%s://%s%s", base.Scheme, base.Host, ref)
	}

	// 处理相对路径
	basePath := base.Path
	if basePath == "" {
		basePath = "/"
	}
	// 移除最后一个路径段
	lastSlash := strings.LastIndex(basePath, "/")
	if lastSlash >= 0 {
		basePath = basePath[:lastSlash+1]
	}
	return fmt.Sprintf("%s://%s%s%s", base.Scheme, base.Host, basePath, ref)
}

// parseURL 是一个简单的 URL 解析辅助函数
type parsedURL struct {
	Scheme string
	Host   string
	Path   string
}

func parseURL(rawURL string) (*parsedURL, error) {
	result := &parsedURL{}

	// 解析 scheme
	if strings.HasPrefix(rawURL, "https://") {
		result.Scheme = "https"
		rawURL = rawURL[8:]
	} else if strings.HasPrefix(rawURL, "http://") {
		result.Scheme = "http"
		rawURL = rawURL[7:]
	} else {
		return nil, fmt.Errorf("invalid URL scheme")
	}

	// 分离 host 和 path
	slashIndex := strings.Index(rawURL, "/")
	if slashIndex >= 0 {
		result.Host = rawURL[:slashIndex]
		result.Path = rawURL[slashIndex:]
	} else {
		result.Host = rawURL
		result.Path = "/"
	}

	return result, nil
}

// ShouldFollowRedirect 检查是否应该跟随重定向（同主机/同域名检查）
func ShouldFollowRedirect(currentURL, nextURL string) bool {
	current, err := parseURL(currentURL)
	if err != nil {
		return false
	}
	next, err := parseURL(nextURL)
	if err != nil {
		return false
	}

	h1 := strings.ToLower(current.Host)
	h2 := strings.ToLower(next.Host)

	// 完全相同
	if h1 == h2 {
		return true
	}

	// 检查子域名关系
	// example.com -> sub.example.com 或 sub.example.com -> example.com
	if strings.HasSuffix(h2, "."+h1) || strings.HasSuffix(h1, "."+h2) {
		return true
	}

	return false
}
