package webscan

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"moongazing/config"
	"moongazing/scanner/core"
)

// DirScanResult represents directory scan result
type DirScanResult struct {
	Target       string     `json:"target"`
	TotalChecked int        `json:"total_checked"`
	Found        int        `json:"found"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      time.Time  `json:"end_time"`
	Duration     string     `json:"duration"`
	Results      []core.DirEntry `json:"results"`
}

// getWordlistFromConfig loads directory wordlist from configuration
func getWordlistFromConfig() []string {
	wordlist := config.GetDirectories()
	if len(wordlist) > 0 {
		return wordlist
	}
	// Fallback to minimal defaults
	return []string{"admin", "api", "login", "backup", "config", ".git", ".env"}
}

// getExtensionsFromConfig loads backup extensions from configuration
func getExtensionsFromConfig() []string {
	exts := config.GetBackupExtensions()
	// Always include empty extension for directory scanning
	result := []string{""}
	if len(exts) > 0 {
		result = append(result, exts...)
	} else {
		result = append(result, ".php", ".asp", ".aspx", ".jsp", ".html", ".bak", ".old", ".zip", ".sql")
	}
	return result
}

// DirBrute performs directory brute force scanning
func (s *ContentScanner) DirBrute(ctx context.Context, target string, wordlist []string, extensions []string) *DirScanResult {
	result := &DirScanResult{
		Target:    target,
		StartTime: time.Now(),
		Results:   make([]core.DirEntry, 0),
	}

	if wordlist == nil {
		wordlist = s.Wordlist
	}
	if extensions == nil {
		extensions = s.Extensions
	}

	// Normalize target URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	target = strings.TrimSuffix(target, "/")

	// Build paths to check
	var paths []string
	for _, word := range wordlist {
		for _, ext := range extensions {
			paths = append(paths, "/"+word+ext)
		}
	}

	// 重置过滤器状态（每次扫描开始前）
	if s.Filter != nil {
		s.Filter.Reset()
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, s.Concurrency)

	for _, path := range paths {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			entry := s.checkPathWithRedirect(ctx, target, p)
			if entry != nil {
				// 应用去重过滤
				if s.Filter != nil && s.Filter.ShouldFilter(entry) {
					// 页面被判定为重复/无效，跳过
					mu.Lock()
					result.TotalChecked++
					mu.Unlock()
					return
				}

				mu.Lock()
				result.Results = append(result.Results, *entry)
				result.Found++
				result.TotalChecked++
				mu.Unlock()
			} else {
				mu.Lock()
				result.TotalChecked++
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()

	// Sort results by status code
	sort.Slice(result.Results, func(i, j int) bool {
		return result.Results[i].StatusCode < result.Results[j].StatusCode
	})

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime).String()
	return result
}

// checkPathWithRedirect checks if a path exists and follows redirects to final page
func (s *ContentScanner) checkPathWithRedirect(ctx context.Context, baseURL, path string) *core.DirEntry {
	currentURL := baseURL + path
	originalURL := currentURL

	// 跟随重定向（最多 MaxRedirects 次）
	for redirectCount := 0; redirectCount <= s.MaxRedirects; redirectCount++ {
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", s.UserAgent)

		resp, err := s.HTTPClient.Do(req)
		if err != nil {
			return nil
		}

		// 读取响应体
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768)) // 32KB 足够检测重定向
		resp.Body.Close()

		// 检查是否为服务器端重定向 (3xx)
		if s.FollowRedirect && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location != "" {
				// 解析重定向 URL
				nextURL := core.ResolveRedirectURL(currentURL, location)
				if nextURL != "" && core.ShouldFollowRedirect(currentURL, nextURL) {
					currentURL = nextURL
					continue
				}
			}
		}

		// 检查是否为客户端重定向 (meta refresh / JS)
		if s.FollowRedirect && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			redirectURL := core.DetectClientRedirectURL(string(body))
			if redirectURL != "" {
				nextURL := core.ResolveRedirectURL(currentURL, redirectURL)
				if nextURL != "" && core.ShouldFollowRedirect(currentURL, nextURL) {
					currentURL = nextURL
					continue
				}
			}
		}

		// 已到达最终页面，进行判断
		// 过滤常见的无效状态码
		if resp.StatusCode == 404 || resp.StatusCode == 400 {
			return nil
		}

		entry := &core.DirEntry{
			URL:           originalURL, // 保留原始扫描 URL
			Path:          path,
			StatusCode:    resp.StatusCode,
			ContentType:   resp.Header.Get("Content-Type"),
			ContentLength: int64(len(body)),
		}

		// 如果发生了重定向，记录最终 URL
		if currentURL != originalURL {
			entry.RedirectTo = currentURL
		}

		// 提取标题（用于去重判断）
		if strings.Contains(entry.ContentType, "text/html") {
			entry.Title = core.ExtractTitle(string(body))
		}

		return entry
	}

	return nil
}

// checkPath checks if a path exists (original method, kept for compatibility)
func (s *ContentScanner) checkPath(ctx context.Context, baseURL, path string) *core.DirEntry {
	url := baseURL + path

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", s.UserAgent)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Filter common non-interesting status codes
	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 500 {
		return nil
	}

	entry := &core.DirEntry{
		URL:           url,
		Path:          path,
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
	}

	// Handle redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		entry.RedirectTo = resp.Header.Get("Location")
	}

	// Try to get title for HTML pages
	if strings.Contains(entry.ContentType, "text/html") && resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
		entry.Title = core.ExtractTitle(string(body))
	}

	return entry
}

// QuickDirScan performs a quick directory scan with common paths
func (s *ContentScanner) QuickDirScan(ctx context.Context, target string) *DirScanResult {
	quickList := s.Wordlist
	if len(quickList) > 50 {
		quickList = quickList[:50]
	}
	return s.DirBrute(ctx, target, quickList, []string{""})
}
