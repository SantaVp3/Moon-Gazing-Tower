package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// 日志文件
var logFile *os.File

func log(format string, args ...interface{}) {
	msg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	fmt.Print(msg)
	if logFile != nil {
		logFile.WriteString(msg)
	}
}

// 简单的子域名检查结果
type SubdomainCheckResult struct {
	Subdomain  string
	FullDomain string
	IPs        []string
	Alive      bool
}

// 检查子域名是否存在
func checkSubdomain(ctx context.Context, subdomain, domain string) *SubdomainCheckResult {
	fullDomain := subdomain + "." + domain
	result := &SubdomainCheckResult{
		Subdomain:  subdomain,
		FullDomain: fullDomain,
		Alive:      false,
	}

	// DNS 查询
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIP(queryCtx, "ip4", fullDomain)
	if err == nil && len(ips) > 0 {
		result.Alive = true
		for _, ip := range ips {
			result.IPs = append(result.IPs, ip.String())
		}
	}

	return result
}

// 获取域名基本信息
func getDomainInfo(domain string) {
	log("===== 获取域名信息: %s =====", domain)

	// A 记录
	ips, err := net.LookupIP(domain)
	if err == nil {
		var ipList []string
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				ipList = append(ipList, ipv4.String())
			}
		}
		log("A 记录 (IPs): %v", ipList)
	} else {
		log("A 记录查询失败: %v", err)
	}

	// CNAME 记录
	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != "" {
		log("CNAME 记录: %s", strings.TrimSuffix(cname, "."))
	}

	// NS 记录
	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		var nsList []string
		for _, ns := range nsRecords {
			nsList = append(nsList, strings.TrimSuffix(ns.Host, "."))
		}
		log("NS 记录: %v", nsList)
	}

	// MX 记录
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		var mxList []string
		for _, mx := range mxRecords {
			mxList = append(mxList, fmt.Sprintf("%s (优先级: %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
		log("MX 记录: %v", mxList)
	}

	// TXT 记录
	txtRecords, err := net.LookupTXT(domain)
	if err == nil && len(txtRecords) > 0 {
		log("TXT 记录: %v", txtRecords)
	}

	log("")
}

// 测试根域名提取
func testExtractRootDomain() {
	log("===== 测试根域名提取功能 =====")

	// 二级域名后缀列表
	secondLevelTLDs := map[string]bool{
		"com.cn": true, "net.cn": true, "org.cn": true,
		"co.uk": true, "org.uk": true,
		"co.jp": true, "com.au": true,
	}

	extractRootDomain := func(domain string) string {
		domain = strings.ToLower(strings.TrimSpace(domain))
		domain = strings.TrimSuffix(domain, ".")
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return domain
		}
		if len(parts) >= 3 {
			possibleTLD := parts[len(parts)-2] + "." + parts[len(parts)-1]
			if secondLevelTLDs[possibleTLD] {
				if len(parts) >= 3 {
					return parts[len(parts)-3] + "." + possibleTLD
				}
				return domain
			}
		}
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}

	testCases := []struct {
		input    string
		expected string
	}{
		{"www.example.com", "example.com"},
		{"api.test.example.com", "example.com"},
		{"www.example.com.cn", "example.com.cn"},
		{"sub.test.example.co.uk", "example.co.uk"},
		{"example.com", "example.com"},
		{"mail.google.com", "google.com"},
	}

	passed := 0
	for _, tc := range testCases {
		result := extractRootDomain(tc.input)
		status := "✓ PASS"
		if result != tc.expected {
			status = "✗ FAIL"
		} else {
			passed++
		}
		log("%s: %s -> %s (期望: %s)", status, tc.input, result, tc.expected)
	}
	log("根域名提取测试: %d/%d 通过\n", passed, len(testCases))
}

// 测试子域名枚举
func testSubdomainEnumeration(domain string) {
	log("===== 测试子域名枚举: %s =====", domain)

	// 常用子域名字典
	wordlist := []string{
		"www", "mail", "ftp", "admin", "api", "dev", "test", "blog",
		"shop", "m", "mobile", "app", "static", "cdn", "img", "images",
		"video", "news", "forum", "support", "help", "docs", "wiki",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	startTime := time.Now()
	var found []SubdomainCheckResult

	log("开始扫描，字典大小: %d", len(wordlist))

	for _, sub := range wordlist {
		select {
		case <-ctx.Done():
			log("扫描超时")
			break
		default:
			result := checkSubdomain(ctx, sub, domain)
			if result.Alive {
				found = append(found, *result)
				log("发现: %s -> %v", result.FullDomain, result.IPs)
			}
		}
	}

	duration := time.Since(startTime)
	log("")
	log("===== 扫描结果汇总 =====")
	log("目标域名: %s", domain)
	log("扫描耗时: %v", duration)
	log("检查数量: %d", len(wordlist))
	log("发现数量: %d", len(found))

	if len(found) > 0 {
		log("")
		log("发现的子域名:")
		for i, r := range found {
			log("  %d. %s (IPs: %v)", i+1, r.FullDomain, r.IPs)
		}
	}
	log("")
}

func main() {
	// 创建日志文件
	var err error
	logFile, err = os.Create("subdomain_test.log")
	if err != nil {
		fmt.Printf("警告: 无法创建日志文件: %v\n", err)
	} else {
		defer logFile.Close()
	}

	log("=========================================")
	log("       子域名扫描服务测试")
	log("=========================================")
	log("")

	// 获取测试域名
	testDomain := "example.com"
	if len(os.Args) > 1 {
		testDomain = os.Args[1]
	}

	// 交互式选择
	fmt.Println("\n请选择测试项目:")
	fmt.Println("1. 测试根域名提取功能")
	fmt.Println("2. 获取域名基本信息")
	fmt.Println("3. 测试子域名枚举")
	fmt.Println("4. 运行所有测试")
	fmt.Println("5. 测试工具可用性")
	fmt.Printf("\n请输入选项 (默认4): ")

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		input = "4"
	}

	fmt.Printf("\n目标域名: %s (可通过命令行参数修改)\n\n", testDomain)

	switch input {
	case "1":
		testExtractRootDomain()
	case "2":
		getDomainInfo(testDomain)
	case "3":
		testSubdomainEnumeration(testDomain)
	case "4":
		testExtractRootDomain()
		getDomainInfo(testDomain)
		testSubdomainEnumeration(testDomain)
	case "5":
		testToolsAvailability()
	default:
		fmt.Println("无效选项")
	}

	log("=========================================")
	log("       测试完成")
	log("=========================================")
	log("日志已保存到: subdomain_test.log")
}

// testToolsAvailability 测试工具可用性
func testToolsAvailability() {
	log("===== 测试工具可用性 =====")
	
	// 获取工具目录
	toolsDir := getToolsDir()
	log("工具目录: %s", toolsDir)
	
	// 检测各工具
	tools := []string{"rustscan", "katana", "rad"}
	
	for _, tool := range tools {
		log("")
		log("检测 %s ...", tool)
		toolPath := getToolPath(tool)
		if toolPath != "" && fileExists(toolPath) {
			log("✓ %s 存在: %s", tool, toolPath)
			
			// 尝试执行版本检查
			cmd := exec.Command(toolPath, "-h")
			output, err := cmd.CombinedOutput()
			if err == nil {
				log("✓ %s 可执行", tool)
				// 只显示前几行
				lines := strings.Split(string(output), "\n")
				for i, line := range lines {
					if i < 2 && line != "" {
						log("  %s", line)
					}
				}
			} else {
				log("! %s 执行返回错误 (可能正常): %v", tool, err)
			}
		} else {
			log("✗ %s 不存在", tool)
		}
		
		// 检查 PATH 中
		if path, err := exec.LookPath(tool); err == nil {
			log("✓ %s 在 PATH 中: %s", tool, path)
		}
	}
	
	log("")
}

// getToolPath 获取工具路径
func getToolPath(name string) string {
	toolsDir := getToolsDir()
	
	var osDir string
	switch runtime.GOOS {
	case "darwin":
		osDir = "darwin"
	case "linux":
		osDir = "linux"
	case "windows":
		osDir = "win"
		name = name + ".exe"
	default:
		return ""
	}
	
	return filepath.Join(toolsDir, osDir, name)
}

// getToolsDir 获取工具目录
func getToolsDir() string {
	execPath, err := os.Executable()
	if err != nil {
		return filepath.Join(".", "tools")
	}
	execDir := filepath.Dir(execPath)
	
	possiblePaths := []string{
		filepath.Join(execDir, "tools"),
		filepath.Join(execDir, "..", "tools"),
		filepath.Join(".", "tools"),
		filepath.Join("..", "tools"),
	}
	
	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			absPath, _ := filepath.Abs(p)
			return absPath
		}
	}
	
	return filepath.Join(execDir, "tools")
}

// fileExists 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
