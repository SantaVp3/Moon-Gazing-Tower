package monitor

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// PageMonitor 页面变化监控器
type PageMonitor struct {
	client       *http.Client
	pages        map[string]*MonitoredPage
	mu           sync.RWMutex
	stopCh       chan struct{}
	changeCallback func(*PageChange)
}

// MonitoredPage 被监控的页面
type MonitoredPage struct {
	ID            string            `json:"id"`
	URL           string            `json:"url"`
	Name          string            `json:"name"`
	Interval      time.Duration     `json:"interval"`
	MonitorType   MonitorType       `json:"monitor_type"`
	Selector      string            `json:"selector,omitempty"`      // CSS 选择器
	Keywords      []string          `json:"keywords,omitempty"`      // 关键词监控
	Headers       map[string]string `json:"headers,omitempty"`       // 自定义请求头
	Enabled       bool              `json:"enabled"`
	
	// 状态
	LastCheck     time.Time         `json:"last_check"`
	LastHash      string            `json:"last_hash"`
	LastContent   string            `json:"last_content,omitempty"`
	LastStatus    int               `json:"last_status"`
	ChangeCount   int               `json:"change_count"`
	ErrorCount    int               `json:"error_count"`
	LastError     string            `json:"last_error,omitempty"`
	
	// 内部控制
	ticker        *time.Ticker      `json:"-"`
	stopCh        chan struct{}     `json:"-"`
}

// MonitorType 监控类型
type MonitorType string

const (
	MonitorTypeFullPage MonitorType = "full_page"   // 完整页面内容
	MonitorTypeSelector MonitorType = "selector"    // CSS 选择器内容
	MonitorTypeKeyword  MonitorType = "keyword"     // 关键词出现/消失
	MonitorTypeStatus   MonitorType = "status"      // HTTP 状态码
	MonitorTypeHash     MonitorType = "hash"        // 内容哈希
	MonitorTypeTitle    MonitorType = "title"       // 页面标题
)

// PageChange 页面变化记录
type PageChange struct {
	PageID      string      `json:"page_id"`
	URL         string      `json:"url"`
	ChangeType  string      `json:"change_type"`
	OldContent  string      `json:"old_content,omitempty"`
	NewContent  string      `json:"new_content,omitempty"`
	OldHash     string      `json:"old_hash,omitempty"`
	NewHash     string      `json:"new_hash,omitempty"`
	OldStatus   int         `json:"old_status,omitempty"`
	NewStatus   int         `json:"new_status,omitempty"`
	Diff        []DiffLine  `json:"diff,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// DiffLine 差异行
type DiffLine struct {
	Type    string `json:"type"` // add, remove, same
	Content string `json:"content"`
	Line    int    `json:"line"`
}

// MonitorConfig 监控配置
type MonitorConfig struct {
	URL         string            `json:"url"`
	Name        string            `json:"name"`
	Interval    int               `json:"interval"` // 秒
	MonitorType MonitorType       `json:"monitor_type"`
	Selector    string            `json:"selector,omitempty"`
	Keywords    []string          `json:"keywords,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// NewPageMonitor 创建页面监控器
func NewPageMonitor() *PageMonitor {
	return &PageMonitor{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		pages:  make(map[string]*MonitoredPage),
		stopCh: make(chan struct{}),
	}
}

// SetChangeCallback 设置变化回调
func (m *PageMonitor) SetChangeCallback(callback func(*PageChange)) {
	m.changeCallback = callback
}

// AddPage 添加监控页面
func (m *PageMonitor) AddPage(config MonitorConfig) (*MonitoredPage, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("URL is required")
	}
	
	if config.Interval < 10 {
		config.Interval = 60 // 默认 60 秒
	}
	
	if config.MonitorType == "" {
		config.MonitorType = MonitorTypeFullPage
	}
	
	id := generatePageID(config.URL)
	
	page := &MonitoredPage{
		ID:          id,
		URL:         config.URL,
		Name:        config.Name,
		Interval:    time.Duration(config.Interval) * time.Second,
		MonitorType: config.MonitorType,
		Selector:    config.Selector,
		Keywords:    config.Keywords,
		Headers:     config.Headers,
		Enabled:     true,
		stopCh:      make(chan struct{}),
	}
	
	// 首次获取内容
	if err := m.fetchAndStore(page); err != nil {
		page.LastError = err.Error()
		page.ErrorCount++
	}
	
	m.mu.Lock()
	m.pages[id] = page
	m.mu.Unlock()
	
	// 启动监控
	go m.monitorPage(page)
	
	return page, nil
}

// RemovePage 移除监控页面
func (m *PageMonitor) RemovePage(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	page, ok := m.pages[id]
	if !ok {
		return fmt.Errorf("page not found")
	}
	
	// 停止监控
	close(page.stopCh)
	if page.ticker != nil {
		page.ticker.Stop()
	}
	
	delete(m.pages, id)
	return nil
}

// GetPage 获取页面信息
func (m *PageMonitor) GetPage(id string) (*MonitoredPage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pages[id], m.pages[id] != nil
}

// GetAllPages 获取所有页面
func (m *PageMonitor) GetAllPages() []*MonitoredPage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	pages := make([]*MonitoredPage, 0, len(m.pages))
	for _, p := range m.pages {
		pages = append(pages, p)
	}
	return pages
}

// EnablePage 启用页面监控
func (m *PageMonitor) EnablePage(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	page, ok := m.pages[id]
	if !ok {
		return fmt.Errorf("page not found")
	}
	
	page.Enabled = enabled
	return nil
}

// CheckNow 立即检查页面
func (m *PageMonitor) CheckNow(id string) (*PageChange, error) {
	m.mu.RLock()
	page, ok := m.pages[id]
	m.mu.RUnlock()
	
	if !ok {
		return nil, fmt.Errorf("page not found")
	}
	
	return m.checkPage(page)
}

// monitorPage 监控页面循环
func (m *PageMonitor) monitorPage(page *MonitoredPage) {
	page.ticker = time.NewTicker(page.Interval)
	defer page.ticker.Stop()
	
	for {
		select {
		case <-page.stopCh:
			return
		case <-m.stopCh:
			return
		case <-page.ticker.C:
			if !page.Enabled {
				continue
			}
			
			change, err := m.checkPage(page)
			if err != nil {
				m.mu.Lock()
				page.LastError = err.Error()
				page.ErrorCount++
				m.mu.Unlock()
				continue
			}
			
			if change != nil && m.changeCallback != nil {
				m.changeCallback(change)
			}
		}
	}
}

// checkPage 检查页面变化
func (m *PageMonitor) checkPage(page *MonitoredPage) (*PageChange, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", page.URL, nil)
	if err != nil {
		return nil, err
	}
	
	// 设置默认 User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	// 设置自定义请求头
	for k, v := range page.Headers {
		req.Header.Set(k, v)
	}
	
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var change *PageChange
	
	switch page.MonitorType {
	case MonitorTypeFullPage:
		change = m.checkFullPage(page, body, resp.StatusCode)
	case MonitorTypeSelector:
		change = m.checkSelector(page, body, resp.StatusCode)
	case MonitorTypeKeyword:
		change = m.checkKeywords(page, body, resp.StatusCode)
	case MonitorTypeStatus:
		change = m.checkStatus(page, resp.StatusCode)
	case MonitorTypeHash:
		change = m.checkHash(page, body, resp.StatusCode)
	case MonitorTypeTitle:
		change = m.checkTitle(page, body, resp.StatusCode)
	}
	
	// 更新状态
	m.mu.Lock()
	page.LastCheck = time.Now()
	page.LastStatus = resp.StatusCode
	page.LastError = ""
	m.mu.Unlock()
	
	return change, nil
}

// checkFullPage 检查完整页面内容
func (m *PageMonitor) checkFullPage(page *MonitoredPage, body []byte, status int) *PageChange {
	// 清理 HTML 获取纯文本
	content := extractText(string(body))
	hash := hashContent(content)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if page.LastHash == "" {
		page.LastHash = hash
		page.LastContent = truncate(content, 10000)
		return nil
	}
	
	if page.LastHash != hash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "content",
			OldHash:    page.LastHash,
			NewHash:    hash,
			OldContent: truncate(page.LastContent, 1000),
			NewContent: truncate(content, 1000),
			Diff:       generateDiff(page.LastContent, content),
			Timestamp:  time.Now(),
		}
		
		page.LastHash = hash
		page.LastContent = truncate(content, 10000)
		page.ChangeCount++
		
		return change
	}
	
	return nil
}

// checkSelector 检查选择器内容
func (m *PageMonitor) checkSelector(page *MonitoredPage, body []byte, status int) *PageChange {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	
	var content strings.Builder
	doc.Find(page.Selector).Each(func(i int, s *goquery.Selection) {
		content.WriteString(s.Text())
		content.WriteString("\n")
	})
	
	text := strings.TrimSpace(content.String())
	hash := hashContent(text)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if page.LastHash == "" {
		page.LastHash = hash
		page.LastContent = text
		return nil
	}
	
	if page.LastHash != hash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "selector",
			OldHash:    page.LastHash,
			NewHash:    hash,
			OldContent: page.LastContent,
			NewContent: text,
			Timestamp:  time.Now(),
		}
		
		page.LastHash = hash
		page.LastContent = text
		page.ChangeCount++
		
		return change
	}
	
	return nil
}

// checkKeywords 检查关键词
func (m *PageMonitor) checkKeywords(page *MonitoredPage, body []byte, status int) *PageChange {
	content := string(body)
	
	var foundKeywords []string
	for _, kw := range page.Keywords {
		if strings.Contains(strings.ToLower(content), strings.ToLower(kw)) {
			foundKeywords = append(foundKeywords, kw)
		}
	}
	
	keywordsHash := hashContent(strings.Join(foundKeywords, ","))
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if page.LastHash == "" {
		page.LastHash = keywordsHash
		page.LastContent = strings.Join(foundKeywords, ",")
		return nil
	}
	
	if page.LastHash != keywordsHash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "keyword",
			OldContent: page.LastContent,
			NewContent: strings.Join(foundKeywords, ","),
			Timestamp:  time.Now(),
		}
		
		page.LastHash = keywordsHash
		page.LastContent = strings.Join(foundKeywords, ",")
		page.ChangeCount++
		
		return change
	}
	
	return nil
}

// checkStatus 检查状态码
func (m *PageMonitor) checkStatus(page *MonitoredPage, status int) *PageChange {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if page.LastStatus == 0 {
		page.LastStatus = status
		return nil
	}
	
	if page.LastStatus != status {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "status",
			OldStatus:  page.LastStatus,
			NewStatus:  status,
			Timestamp:  time.Now(),
		}
		
		page.LastStatus = status
		page.ChangeCount++
		
		return change
	}
	
	return nil
}

// checkHash 检查内容哈希
func (m *PageMonitor) checkHash(page *MonitoredPage, body []byte, status int) *PageChange {
	hash := hashContent(string(body))
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if page.LastHash == "" {
		page.LastHash = hash
		return nil
	}
	
	if page.LastHash != hash {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "hash",
			OldHash:    page.LastHash,
			NewHash:    hash,
			Timestamp:  time.Now(),
		}
		
		page.LastHash = hash
		page.ChangeCount++
		
		return change
	}
	
	return nil
}

// checkTitle 检查页面标题
func (m *PageMonitor) checkTitle(page *MonitoredPage, body []byte, status int) *PageChange {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return nil
	}
	
	title := doc.Find("title").Text()
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if page.LastContent == "" {
		page.LastContent = title
		return nil
	}
	
	if page.LastContent != title {
		change := &PageChange{
			PageID:     page.ID,
			URL:        page.URL,
			ChangeType: "title",
			OldContent: page.LastContent,
			NewContent: title,
			Timestamp:  time.Now(),
		}
		
		page.LastContent = title
		page.ChangeCount++
		
		return change
	}
	
	return nil
}

// fetchAndStore 获取并存储初始内容
func (m *PageMonitor) fetchAndStore(page *MonitoredPage) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", page.URL, nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range page.Headers {
		req.Header.Set(k, v)
	}
	
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	
	page.LastStatus = resp.StatusCode
	page.LastCheck = time.Now()
	
	switch page.MonitorType {
	case MonitorTypeFullPage, MonitorTypeHash:
		content := extractText(string(body))
		page.LastHash = hashContent(content)
		page.LastContent = truncate(content, 10000)
	case MonitorTypeSelector:
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		var content strings.Builder
		doc.Find(page.Selector).Each(func(i int, s *goquery.Selection) {
			content.WriteString(s.Text())
		})
		page.LastContent = content.String()
		page.LastHash = hashContent(page.LastContent)
	case MonitorTypeTitle:
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		page.LastContent = doc.Find("title").Text()
	case MonitorTypeKeyword:
		var found []string
		for _, kw := range page.Keywords {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(kw)) {
				found = append(found, kw)
			}
		}
		page.LastContent = strings.Join(found, ",")
		page.LastHash = hashContent(page.LastContent)
	}
	
	return nil
}

// Stop 停止所有监控
func (m *PageMonitor) Stop() {
	close(m.stopCh)
	
	m.mu.Lock()
	defer m.mu.Unlock()
	
	for _, page := range m.pages {
		close(page.stopCh)
		if page.ticker != nil {
			page.ticker.Stop()
		}
	}
}

// 工具函数

func generatePageID(url string) string {
	hash := md5.Sum([]byte(url))
	return hex.EncodeToString(hash[:8])
}

func hashContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

func extractText(html string) string {
	// 移除 script 和 style
	scriptRe := regexp.MustCompile(`<script[^>]*>[\s\S]*?</script>`)
	html = scriptRe.ReplaceAllString(html, "")
	
	styleRe := regexp.MustCompile(`<style[^>]*>[\s\S]*?</style>`)
	html = styleRe.ReplaceAllString(html, "")
	
	// 移除所有 HTML 标签
	tagRe := regexp.MustCompile(`<[^>]+>`)
	text := tagRe.ReplaceAllString(html, " ")
	
	// 清理多余空白
	spaceRe := regexp.MustCompile(`\s+`)
	text = spaceRe.ReplaceAllString(text, " ")
	
	return strings.TrimSpace(text)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func generateDiff(old, new string) []DiffLine {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")
	
	diff := make([]DiffLine, 0)
	
	// 简单 diff 实现
	maxLen := len(oldLines)
	if len(newLines) > maxLen {
		maxLen = len(newLines)
	}
	
	for i := 0; i < maxLen; i++ {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}
		
		if oldLine != newLine {
			if oldLine != "" {
				diff = append(diff, DiffLine{
					Type:    "remove",
					Content: oldLine,
					Line:    i + 1,
				})
			}
			if newLine != "" {
				diff = append(diff, DiffLine{
					Type:    "add",
					Content: newLine,
					Line:    i + 1,
				})
			}
		}
	}
	
	// 限制 diff 数量
	if len(diff) > 100 {
		diff = diff[:100]
	}
	
	return diff
}
