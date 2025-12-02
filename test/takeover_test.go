package test

import (
	"context"
	"testing"
	"time"

	"moongazing/scanner/subdomain"
)

// TestTakeoverScanner 测试子域名接管检测器
func TestTakeoverScanner(t *testing.T) {
	ts := subdomain.NewTakeoverScanner(10)

	t.Run("GetFingerprints", func(t *testing.T) {
		fps := ts.GetFingerprints()
		if len(fps) == 0 {
			t.Error("Expected fingerprints, got none")
		}
		t.Logf("Loaded %d fingerprints", len(fps))

		// 检查一些常见服务是否存在
		services := make(map[string]bool)
		for _, fp := range fps {
			services[fp.Service] = true
		}

		expectedServices := []string{
			"GitHub Pages",
			"Amazon S3",
			"Heroku",
			"Azure",
			"Netlify",
		}

		for _, svc := range expectedServices {
			if !services[svc] {
				t.Errorf("Expected service %s in fingerprints", svc)
			}
		}
	})
}

// TestTakeoverScanSingleDomain 测试单个域名扫描
func TestTakeoverScanSingleDomain(t *testing.T) {
	ts := subdomain.NewTakeoverScanner(10)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 测试一个正常的域名（不应该存在接管风险）
	t.Run("NormalDomain", func(t *testing.T) {
		result, err := ts.Scan(ctx, "www.google.com")
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}

		t.Logf("Domain: %s", result.Domain)
		t.Logf("CNAME: %s", result.CNAME)
		t.Logf("Vulnerable: %v", result.Vulnerable)
		t.Logf("Reason: %s", result.Reason)

		if result.Vulnerable {
			t.Log("Warning: google.com detected as vulnerable (unexpected)")
		}
	})

	// 测试一个不存在的域名
	t.Run("NonExistentDomain", func(t *testing.T) {
		result, err := ts.Scan(ctx, "this-domain-definitely-does-not-exist-12345.com")
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}

		t.Logf("Domain: %s", result.Domain)
		t.Logf("CNAME: %s", result.CNAME)
		t.Logf("Reason: %s", result.Reason)
	})
}

// TestTakeoverScanBatch 测试批量扫描
func TestTakeoverScanBatch(t *testing.T) {
	ts := subdomain.NewTakeoverScanner(5)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	domains := []string{
		"www.baidu.com",
		"www.alibaba.com",
		"www.tencent.com",
	}

	results, err := ts.ScanBatch(ctx, domains)
	if err != nil {
		t.Fatalf("Batch scan error: %v", err)
	}

	if len(results) != len(domains) {
		t.Errorf("Expected %d results, got %d", len(domains), len(results))
	}

	for _, r := range results {
		t.Logf("Domain: %s, CNAME: %s, Vulnerable: %v, Service: %s",
			r.Domain, r.CNAME, r.Vulnerable, r.Service)
	}
}

// TestCNAMEMatching 测试 CNAME 匹配逻辑
func TestCNAMEMatching(t *testing.T) {
	ts := scanner.NewTakeoverScanner(10)
	fps := ts.GetFingerprints()

	testCases := []struct {
		cname           string
		expectedService string
		shouldMatch     bool
	}{
		{"example.github.io", "GitHub Pages", true},
		{"mybucket.s3.amazonaws.com", "Amazon S3", true},
		{"myapp.herokuapp.com", "Heroku", true},
		{"mysite.azurewebsites.net", "Azure", true},
		{"mysite.netlify.app", "Netlify", true},
		{"mysite.vercel.app", "Vercel", true},
		{"www.google.com", "", false},
		{"cdn.cloudflare.com", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.cname, func(t *testing.T) {
			matched := false
			matchedService := ""

			for _, fp := range fps {
				for _, pattern := range fp.CNames {
					if containsIgnoreCase(tc.cname, pattern) {
						matched = true
						matchedService = fp.Service
						break
					}
				}
				if matched {
					break
				}
			}

			if tc.shouldMatch && !matched {
				t.Errorf("Expected %s to match service %s, but no match found", tc.cname, tc.expectedService)
			}

			if tc.shouldMatch && matched && matchedService != tc.expectedService {
				t.Errorf("Expected service %s, got %s for CNAME %s", tc.expectedService, matchedService, tc.cname)
			}

			if !tc.shouldMatch && matched {
				t.Errorf("Expected %s not to match any service, but matched %s", tc.cname, matchedService)
			}
		})
	}
}

// containsIgnoreCase 检查字符串是否包含子串（忽略大小写）
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(substr) > 0 && findIgnoreCase(s, substr))
}

func findIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalIgnoreCase(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// BenchmarkTakeoverScan 性能测试
func BenchmarkTakeoverScan(b *testing.B) {
	ts := scanner.NewTakeoverScanner(10)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts.Scan(ctx, "www.example.com")
	}
}

// BenchmarkTakeoverScanBatch 批量扫描性能测试
func BenchmarkTakeoverScanBatch(b *testing.B) {
	ts := scanner.NewTakeoverScanner(20)
	ctx := context.Background()

	domains := []string{
		"www.example1.com",
		"www.example2.com",
		"www.example3.com",
		"www.example4.com",
		"www.example5.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts.ScanBatch(ctx, domains)
	}
}
