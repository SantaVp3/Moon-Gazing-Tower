package scanner

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

// ScreenshotScanner 截图扫描器
type ScreenshotScanner struct {
	outputDir string
	timeout   time.Duration
}

// NewScreenshotScanner 创建截图扫描器
func NewScreenshotScanner(outputDir string) *ScreenshotScanner {
	if outputDir == "" {
		outputDir = "./screenshots"
	}
	
	// 确保目录存在
	os.MkdirAll(outputDir, 0755)
	
	return &ScreenshotScanner{
		outputDir: outputDir,
		timeout:   30 * time.Second,
	}
}

// Screenshot 对URL进行截图
func (s *ScreenshotScanner) Screenshot(url string) (string, error) {
	// 创建chrome上下文
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// 设置超时
	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// 生成文件名
	filename := s.generateFilename(url)
	filepath := filepath.Join(s.outputDir, filename)

	// 截图
	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1920, 1080),
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second), // 等待页面加载
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}

	// 保存文件
	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", fmt.Errorf("save screenshot failed: %w", err)
	}

	return filepath, nil
}

// ScreenshotWithHeadless 使用无头模式截图（更快）
func (s *ScreenshotScanner) ScreenshotWithHeadless(url string) (string, error) {
	// 配置chromedp选项
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// 设置超时
	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// 生成文件名
	filename := s.generateFilename(url)
	filepath := filepath.Join(s.outputDir, filename)

	// 截图
	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.FullScreenshot(&buf, 90),
	)

	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}

	// 保存文件
	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", fmt.Errorf("save screenshot failed: %w", err)
	}

	return filepath, nil
}

// ScreenshotViewport 截取可视区域
func (s *ScreenshotScanner) ScreenshotViewport(url string) (string, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	filename := s.generateFilename(url)
	filepath := filepath.Join(s.outputDir, filename)

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.Sleep(2*time.Second),
		chromedp.CaptureScreenshot(&buf), // 只截取可视区域
	)

	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}

	if err := os.WriteFile(filepath, buf, 0644); err != nil {
		return "", fmt.Errorf("save screenshot failed: %w", err)
	}

	return filepath, nil
}

// BatchScreenshot 批量截图
func (s *ScreenshotScanner) BatchScreenshot(urls []string, concurrency int) map[string]string {
	if concurrency <= 0 {
		concurrency = 5
	}

	results := make(map[string]string)
	semaphore := make(chan struct{}, concurrency)
	done := make(chan struct {
		url      string
		filepath string
	}, len(urls))

	// 启动goroutine
	for _, url := range urls {
		go func(u string) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			filepath, err := s.ScreenshotViewport(u)
			if err != nil {
				filepath = ""
			}
			done <- struct {
				url      string
				filepath string
			}{u, filepath}
		}(url)
	}

	// 收集结果
	for i := 0; i < len(urls); i++ {
		result := <-done
		results[result.url] = result.filepath
	}

	return results
}

// generateFilename 生成截图文件名
func (s *ScreenshotScanner) generateFilename(url string) string {
	// 使用MD5哈希生成文件名
	hash := md5Hash(url)
	timestamp := time.Now().Format("20060102_150405")
	return fmt.Sprintf("screenshot_%s_%s.png", hash[:16], timestamp)
}

// md5Hash 计算MD5哈希
func md5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetScreenshotPath 获取截图保存路径
func (s *ScreenshotScanner) GetScreenshotPath(filename string) string {
	return filepath.Join(s.outputDir, filename)
}

// CleanOldScreenshots 清理旧截图
func (s *ScreenshotScanner) CleanOldScreenshots(days int) error {
	if days <= 0 {
		days = 7
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	return filepath.Walk(s.outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.ModTime().Before(cutoff) {
			return os.Remove(path)
		}

		return nil
	})
}

