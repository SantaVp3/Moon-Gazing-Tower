package test

import (
	"context"
	"testing"
	"time"

	"moongazing/scanner/enscan"
)

// TestENScanScanner 测试 ENScan 扫描器
func TestENScanScanner(t *testing.T) {
	es := enscan.NewENScanScanner()

	t.Run("IsAvailable", func(t *testing.T) {
		available := es.IsAvailable()
		t.Logf("ENScan available: %v", available)
		if !available {
			t.Skip("ENScan not available, skipping tests")
		}
	})

	t.Run("CheckConfig", func(t *testing.T) {
		configPath := es.GetConfigPath()
		t.Logf("Config path: %s", configPath)

		sources, err := es.CheckConfig()
		if err != nil {
			t.Logf("Config check error: %v", err)
			return
		}

		if len(sources) == 0 {
			t.Log("⚠️  No data sources configured!")
			t.Log("📝 Please configure cookies in config.yaml:")
			t.Log("   - aiqicha: 爱企查 Cookie")
			t.Log("   - tianyancha: 天眼查 Cookie")
			t.Log("   - qimai: 七麦数据 Cookie (for APP data)")
		} else {
			t.Logf("✅ Configured sources: %v", sources)
		}
	})
}

// TestENScanQueryCompany 测试公司信息查询
func TestENScanQueryCompany(t *testing.T) {
	es := enscan.NewENScanScanner()
	if !es.IsAvailable() {
		t.Skip("ENScan not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 测试查询小米公司
	t.Run("QueryXiaomi", func(t *testing.T) {
		result, err := es.QueryCompany(ctx, "小米科技有限责任公司", &enscan.ENScanQueryOptions{
			Fields: []string{"app", "wx_app"},
			Source: "aqc",
		})
		if err != nil {
			t.Logf("Query error (may be expected if cookies not configured): %v", err)
			return
		}

		t.Logf("Company: %s", result.Company)
		t.Logf("Apps found: %d", len(result.Apps))
		t.Logf("WxApps found: %d", len(result.WxApps))

		for i, app := range result.Apps {
			if i >= 5 {
				t.Logf("... and %d more apps", len(result.Apps)-5)
				break
			}
			t.Logf("  App: %s", app.Name)
		}

		for i, wxApp := range result.WxApps {
			if i >= 5 {
				t.Logf("... and %d more wxapps", len(result.WxApps)-5)
				break
			}
			t.Logf("  WxApp: %s", wxApp.Name)
		}
	})
}

// TestENScanQueryApps 测试 APP 查询
func TestENScanQueryApps(t *testing.T) {
	es := enscan.NewENScanScanner()
	if !es.IsAvailable() {
		t.Skip("ENScan not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	apps, err := es.QueryApps(ctx, "腾讯科技")
	if err != nil {
		t.Logf("Query error (may be expected): %v", err)
		return
	}

	t.Logf("Found %d apps", len(apps))
	for i, app := range apps {
		if i >= 10 {
			break
		}
		t.Logf("  - %s (Category: %s)", app.Name, app.Category)
	}
}

// TestENScanQueryWxApps 测试微信小程序查询
func TestENScanQueryWxApps(t *testing.T) {
	es := enscan.NewENScanScanner()
	if !es.IsAvailable() {
		t.Skip("ENScan not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wxApps, err := es.QueryWxApps(ctx, "阿里巴巴")
	if err != nil {
		t.Logf("Query error (may be expected): %v", err)
		return
	}

	t.Logf("Found %d wx apps", len(wxApps))
	for i, wxApp := range wxApps {
		if i >= 10 {
			break
		}
		t.Logf("  - %s (AppID: %s)", wxApp.Name, wxApp.AppID)
	}
}

// TestENScanQueryICPs 测试 ICP 备案查询
func TestENScanQueryICPs(t *testing.T) {
	es := enscan.NewENScanScanner()
	if !es.IsAvailable() {
		t.Skip("ENScan not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	icps, err := es.QueryICPs(ctx, "字节跳动")
	if err != nil {
		t.Logf("Query error (may be expected): %v", err)
		return
	}

	t.Logf("Found %d ICP records", len(icps))
	for i, icp := range icps {
		if i >= 10 {
			break
		}
		t.Logf("  - %s (%s)", icp.Domain, icp.ICP)
	}
}

// TestENScanQueryAll 测试查询所有信息
func TestENScanQueryAll(t *testing.T) {
	es := scanner.NewENScanScanner()
	if !es.IsAvailable() {
		t.Skip("ENScan not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	result, err := es.QueryAll(ctx, "百度")
	if err != nil {
		t.Logf("Query error (may be expected): %v", err)
		return
	}

	t.Logf("Company: %s", result.Company)
	t.Logf("Source: %s", result.Source)
	t.Logf("Query Time: %s", result.QueryTime)
	t.Logf("Summary:")
	t.Logf("  - Apps: %d", len(result.Apps))
	t.Logf("  - WxApps: %d", len(result.WxApps))
	t.Logf("  - Wechats: %d", len(result.Wechats))
	t.Logf("  - ICPs: %d", len(result.ICPs))
	t.Logf("  - Weibos: %d", len(result.Weibos))
	t.Logf("  - Copyrights: %d", len(result.Copyrights))
}

// TestENScanBatchQuery 测试批量查询
func TestENScanBatchQuery(t *testing.T) {
	es := scanner.NewENScanScanner()
	if !es.IsAvailable() {
		t.Skip("ENScan not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	companies := []string{
		"小米",
		"华为",
	}

	results, err := es.BatchQuery(ctx, companies, &scanner.ENScanQueryOptions{
		Fields: []string{"icp"},
		Source: "aqc",
	})
	if err != nil {
		t.Logf("Batch query error: %v", err)
		return
	}

	t.Logf("Queried %d companies", len(results))
	for _, r := range results {
		t.Logf("  %s: %d ICPs", r.Company, len(r.ICPs))
	}
}
