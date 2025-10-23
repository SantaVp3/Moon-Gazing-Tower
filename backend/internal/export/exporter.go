package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/reconmaster/backend/internal/models"
)

// Exporter 数据导出器
type Exporter struct {
	outputDir string
}

// NewExporter 创建导出器
func NewExporter(outputDir string) *Exporter {
	if outputDir == "" {
		outputDir = "./exports"
	}
	os.MkdirAll(outputDir, 0755)
	return &Exporter{
		outputDir: outputDir,
	}
}

// ExportData 导出数据结构
type ExportData struct {
	Task            *models.Task           `json:"task"`
	Domains         []models.Domain        `json:"domains"`
	IPs             []models.IP            `json:"ips"`
	Ports           []models.Port          `json:"ports"`
	Sites           []models.Site          `json:"sites"`
	URLs            []models.URL           `json:"urls"`
	Vulnerabilities []models.Vulnerability `json:"vulnerabilities"`
	ExportTime      time.Time              `json:"export_time"`
}

// ExportToJSON 导出为JSON
func (e *Exporter) ExportToJSON(data *ExportData) (string, error) {
	filename := fmt.Sprintf("%s/task_%s_%s.json",
		e.outputDir,
		data.Task.ID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return "", err
	}

	return filename, nil
}

// ExportDomainsToCSV 导出域名为CSV
func (e *Exporter) ExportDomainsToCSV(domains []models.Domain, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/domains_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 写入UTF-8 BOM，让Excel正确识别中文
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{"域名", "IP地址", "来源", "CDN", "创建时间"}
	if err := writer.Write(headers); err != nil {
		return "", err
	}

	// 写入数据
	for _, domain := range domains {
		record := []string{
			domain.Domain,
			domain.IPAddress,
			domain.Source,
			fmt.Sprintf("%t", domain.CDN),
			domain.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	return filename, nil
}

// ExportPortsToCSV 导出端口为CSV
func (e *Exporter) ExportPortsToCSV(ports []models.Port, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/ports_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 写入UTF-8 BOM
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{"IP地址", "端口", "协议", "服务", "版本", "Banner"}
	if err := writer.Write(headers); err != nil {
		return "", err
	}

	// 写入数据
	for _, port := range ports {
		record := []string{
			port.IPAddress,
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			port.Service,
			port.Version,
			truncateString(port.Banner, 100),
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	return filename, nil
}

// ExportSitesToCSV 导出站点为CSV
func (e *Exporter) ExportSitesToCSV(sites []models.Site, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/sites_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 写入UTF-8 BOM
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{"URL", "标题", "状态码", "Server", "指纹", "截图"}
	if err := writer.Write(headers); err != nil {
		return "", err
	}

	// 写入数据
	for _, site := range sites {
		fingerprints := ""
		if len(site.Fingerprints) > 0 {
			fingerprintsBytes, _ := json.Marshal(site.Fingerprints)
			fingerprints = string(fingerprintsBytes)
		}

		record := []string{
			site.URL,
			site.Title,
			fmt.Sprintf("%d", site.StatusCode),
			site.Server,
			fingerprints,
			site.Screenshot,
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	return filename, nil
}

// ExportVulnerabilitiesToCSV 导出漏洞为CSV
func (e *Exporter) ExportVulnerabilitiesToCSV(vulns []models.Vulnerability, taskID string) (string, error) {
	filename := fmt.Sprintf("%s/vulnerabilities_%s_%s.csv",
		e.outputDir,
		taskID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 🆕 写入UTF-8 BOM
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{"URL", "类型", "严重性", "标题", "描述", "解决方案"}
	if err := writer.Write(headers); err != nil {
		return "", err
	}

	// 写入数据
	for _, vuln := range vulns {
		record := []string{
			vuln.URL,
			vuln.Type,
			vuln.Severity,
			vuln.Title,
			truncateString(vuln.Description, 200),
			truncateString(vuln.Solution, 200),
		}
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}

	return filename, nil
}

// ExportAll 导出所有数据
func (e *Exporter) ExportAll(data *ExportData) (map[string]string, error) {
	results := make(map[string]string)

	// JSON
	jsonFile, err := e.ExportToJSON(data)
	if err == nil {
		results["json"] = jsonFile
	}

	// 域名CSV
	if len(data.Domains) > 0 {
		csvFile, err := e.ExportDomainsToCSV(data.Domains, data.Task.ID)
		if err == nil {
			results["domains_csv"] = csvFile
		}
	}

	// 端口CSV
	if len(data.Ports) > 0 {
		csvFile, err := e.ExportPortsToCSV(data.Ports, data.Task.ID)
		if err == nil {
			results["ports_csv"] = csvFile
		}
	}

	// 站点CSV
	if len(data.Sites) > 0 {
		csvFile, err := e.ExportSitesToCSV(data.Sites, data.Task.ID)
		if err == nil {
			results["sites_csv"] = csvFile
		}
	}

	// 漏洞CSV
	if len(data.Vulnerabilities) > 0 {
		csvFile, err := e.ExportVulnerabilitiesToCSV(data.Vulnerabilities, data.Task.ID)
		if err == nil {
			results["vulns_csv"] = csvFile
		}
	}

	return results, nil
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// GenerateReport 生成报告
func (e *Exporter) GenerateReport(data *ExportData) (string, error) {
	filename := fmt.Sprintf("%s/report_%s_%s.html",
		e.outputDir,
		data.Task.ID,
		time.Now().Format("20060102_150405"))

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 生成HTML报告
	html := generateHTMLReport(data)
	_, err = file.WriteString(html)
	if err != nil {
		return "", err
	}

	return filename, nil
}

// generateHTMLReport 生成HTML报告
func generateHTMLReport(data *ExportData) string {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ARL扫描报告 - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #666; margin-top: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f9f9f9; padding: 15px; border-radius: 5px; border-left: 4px solid #4CAF50; }
        .stat-card h3 { margin: 0; color: #666; font-size: 14px; }
        .stat-card p { margin: 10px 0 0 0; font-size: 28px; font-weight: bold; color: #333; }
        table { width: 100%%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; font-weight: bold; }
        .severity-low { color: #388e3c; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ARL资产侦察报告</h1>
        
        <div class="info">
            <p><strong>任务名称:</strong> %s</p>
            <p><strong>任务目标:</strong> %s</p>
            <p><strong>扫描时间:</strong> %s</p>
            <p><strong>导出时间:</strong> %s</p>
        </div>

        <h2>资产统计</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>域名数量</h3>
                <p>%d</p>
            </div>
            <div class="stat-card">
                <h3>IP数量</h3>
                <p>%d</p>
            </div>
            <div class="stat-card">
                <h3>开放端口</h3>
                <p>%d</p>
            </div>
            <div class="stat-card">
                <h3>站点数量</h3>
                <p>%d</p>
            </div>
            <div class="stat-card">
                <h3>漏洞数量</h3>
                <p>%d</p>
            </div>
        </div>

        <h2>漏洞列表</h2>
        %s

        <h2>域名列表</h2>
        %s

        <h2>站点列表</h2>
        %s
    </div>
</body>
</html>`,
		data.Task.ID,
		data.Task.Name,
		data.Task.Target,
		data.Task.CreatedAt.Format("2006-01-02 15:04:05"),
		data.ExportTime.Format("2006-01-02 15:04:05"),
		len(data.Domains),
		len(data.IPs),
		len(data.Ports),
		len(data.Sites),
		len(data.Vulnerabilities),
		generateVulnTable(data.Vulnerabilities),
		generateDomainTable(data.Domains),
		generateSiteTable(data.Sites),
	)

	return html
}

func generateVulnTable(vulns []models.Vulnerability) string {
	if len(vulns) == 0 {
		return "<p>未发现漏洞</p>"
	}

	html := "<table><tr><th>URL</th><th>类型</th><th>严重性</th><th>标题</th></tr>"
	for _, v := range vulns {
		severityClass := fmt.Sprintf("severity-%s", v.Severity)
		html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td class='%s'>%s</td><td>%s</td></tr>",
			v.URL, v.Type, severityClass, v.Severity, v.Title)
	}
	html += "</table>"
	return html
}

func generateDomainTable(domains []models.Domain) string {
	if len(domains) == 0 {
		return "<p>未发现域名</p>"
	}

	html := "<table><tr><th>域名</th><th>IP地址</th><th>来源</th></tr>"
	for _, d := range domains {
		html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
			d.Domain, d.IPAddress, d.Source)
	}
	html += "</table>"
	return html
}

func generateSiteTable(sites []models.Site) string {
	if len(sites) == 0 {
		return "<p>未发现站点</p>"
	}

	html := "<table><tr><th>URL</th><th>标题</th><th>状态码</th><th>Server</th></tr>"
	for _, s := range sites {
		html += fmt.Sprintf("<tr><td><a href='%s' target='_blank'>%s</a></td><td>%s</td><td>%d</td><td>%s</td></tr>",
			s.URL, s.URL, s.Title, s.StatusCode, s.Server)
	}
	html += "</table>"
	return html
}
