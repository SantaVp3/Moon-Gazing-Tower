package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v2"
)

// MasscanEngine Masscan扫描引擎
// 参考 MassMap 项目思路：先用 Masscan 快速发现开放端口，再用 Nmap 详细扫描
type MasscanEngine struct {
	rate          int           // Masscan 扫描速率 (packets/sec)
	timeout       time.Duration // 超时时间
	nmapAvailable bool          // Nmap 是否可用
}

// MasscanResult Masscan 扫描结果
type MasscanResult struct {
	IP        string `json:"ip"`
	Port      int    `json:"port,string"`
	Protocol  string `json:"proto"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// MasscanHost 对应 Masscan JSON 输出中的顶级对象（按IP）
type MasscanHost struct {
	IP        string        `json:"ip"`
	Timestamp string        `json:"timestamp"`
	Ports     []MasscanPort `json:"ports"`
}

// MasscanPort 对应 Masscan JSON 输出中 "ports" 数组内的对象
type MasscanPort struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	TTL    int    `json:"ttl"`
}

// NewMasscanEngine 创建 Masscan 扫描引擎
func NewMasscanEngine() *MasscanEngine {
	engine := &MasscanEngine{
		rate:    100000, // 默认 100000 packets/sec，平衡速度和准确性
		timeout: 5 * time.Second,
	}
	engine.nmapAvailable = engine.isNmapAvailable()
	return engine
}

// SetRate 设置扫描速率
func (me *MasscanEngine) SetRate(rate int) {
	me.rate = rate
}

// isMasscanAvailable 检测 Masscan 是否可用
func isMasscanAvailable() bool {
	masscanPath, err := exec.LookPath("masscan")
	if err != nil {
		// 在 PATH 中找不到 masscan
		fmt.Println("========Masscan Check FAILED=========")
		fmt.Printf("Error: 'masscan' executable not found in PATH: %v\n", err)
		fmt.Println("=======================================")
		return false
	}
	fmt.Printf("✓ 'masscan' executable found at: %s\n", masscanPath)

	return true
}

// ScanPorts 使用 Masscan + Nmap 组合扫描端口
// 阶段1：Masscan 快速扫描所有端口
// 阶段2：Nmap 详细扫描开放的端口
func (me *MasscanEngine) ScanPorts(targets []string, ports []int) ([]*PortScanResult, error) {
	if !isMasscanAvailable() {
		return nil, fmt.Errorf("masscan not found, please install: apt install masscan / brew install masscan")
	}

	fmt.Println("=== MassMap-Style Scanning ===")
	fmt.Printf("Stage 1: Masscan rapid discovery (rate: %d pps)\n", me.rate)
	fmt.Printf("Stage 2: Nmap detailed enumeration\n")

	// 阶段1：Masscan 快速扫描
	openPorts, err := me.masscanDiscovery(targets, ports)
	if err != nil {
		return nil, fmt.Errorf("masscan discovery failed: %w", err)
	}

	if len(openPorts) == 0 {
		fmt.Println("No open ports discovered by Masscan")
		return []*PortScanResult{}, nil
	}

	fmt.Printf("✓ Masscan found %d open ports\n", len(openPorts))

	// 阶段2：Nmap 详细扫描（如果可用）
	if me.nmapAvailable {
		fmt.Printf("Stage 2: Nmap detailed scanning %d targets...\n", len(openPorts))
		return me.nmapEnumeration(openPorts)
	}

	// 如果 Nmap 不可用，只返回 Masscan 的结果
	fmt.Println("⚠ Nmap not available, returning basic Masscan results")
	return me.convertMasscanResults(openPorts), nil
}

// masscanDiscovery 使用 Masscan 快速发现开放端口
func (me *MasscanEngine) masscanDiscovery(targets []string, ports []int) (map[string][]int, error) {
	// 构建端口范围字符串
	portRanges := me.buildPortRanges(ports)

	// 构建 Masscan 命令
	args := []string{
		"--rate", strconv.Itoa(me.rate),
		"-p", portRanges,
		"--open", // 只显示开放端口
		"--output-format", "json",
		"--output-filename", "-", // 输出到 stdout
	}

	// 添加目标
	args = append(args, targets...)

	fmt.Printf("Executing: masscan --rate %d -p %s %s\n", me.rate, portRanges, strings.Join(targets, " "))

	fmt.Println("======masscan2======")
	fmt.Println("masscan", args)
	fmt.Println("======masscan2======")

	cmd := exec.Command("masscan", args...)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("======masscan3======")
		fmt.Println(err.Error())
		fmt.Println("======masscan3======")
		return nil, fmt.Errorf("masscan execution failed: %w", err)
	}
	fmt.Println("======masscan4======")
	fmt.Println(output)
	fmt.Println("======masscan4======")

	// 解析 Masscan JSON 输出
	return me.parseMasscanOutput(output)
}

// buildPortRanges 构建端口范围字符串
func (me *MasscanEngine) buildPortRanges(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	// 确保端口是排序的
	sort.Ints(ports)

	var ranges []string
	if len(ports) == 0 {
		return ""
	}

	start := ports[0]
	end := ports[0]

	for i := 1; i < len(ports); i++ {
		// 检查端口是否连续
		if ports[i] == end+1 {
			end = ports[i] // 扩展当前范围
		} else {
			// 发现不连续，保存上一个范围
			if start == end {
				ranges = append(ranges, strconv.Itoa(start))
			} else {
				ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
			}
			// 开始一个新范围
			start = ports[i]
			end = ports[i]
		}
	}

	// 保存最后一个范围
	if start == end {
		ranges = append(ranges, strconv.Itoa(start))
	} else {
		ranges = append(ranges, fmt.Sprintf("%d-%d", start, end))
	}

	return strings.Join(ranges, ",")
}

// parseMasscanOutput 解析 Masscan JSON 输出
func (me *MasscanEngine) parseMasscanOutput(output []byte) (map[string][]int, error) {
	openPorts := make(map[string][]int)

	// 如果输出为空（没有找到任何主机），直接返回空 map
	if len(strings.TrimSpace(string(output))) == 0 {
		return openPorts, nil
	}

	// 定义一个 MasscanHost 切片来接收完整的 JSON 数组
	var results []MasscanHost

	// 将完整的 stdout 输出作为一个 JSON 数组进行解析
	if err := json.Unmarshal(output, &results); err != nil {
		// 截取部分输出来帮助调试
		outputStr := string(output)
		if len(outputStr) > 200 {
			outputStr = outputStr[:200] + "..."
		}
		// 打印你收到的原始日志，帮助调试
		fmt.Printf("======masscan PARSE FAILED======\n")
		fmt.Printf("Error: %v\n", err)
		fmt.Printf("Raw Output (truncated): %s\n", outputStr)
		fmt.Printf("==================================\n")
		return nil, fmt.Errorf("failed to parse masscan JSON array: %w. Output (truncated): %s", err, outputStr)
	}

	// 遍历解析出的每个主机（IP）
	for _, host := range results {
		// 遍历该主机的所有端口
		for _, port := range host.Ports {
			// 检查端口状态
			if port.Status == "open" {
				// 确保 map 中的切片已初始化
				if _, exists := openPorts[host.IP]; !exists {
					openPorts[host.IP] = []int{}
				}
				// 添加开放端口
				openPorts[host.IP] = append(openPorts[host.IP], port.Port)
			}
		}
	}

	fmt.Printf("✓ Parsed %d open ports from masscan output.\n", len(openPorts))
	return openPorts, nil
}

// nmapEnumeration 使用 Nmap 对开放端口进行详细扫描
func (me *MasscanEngine) nmapEnumeration(openPorts map[string][]int) ([]*PortScanResult, error) {
	var allResults []*PortScanResult

	// 对每个 IP 及其开放端口进行 Nmap 扫描
	for ip, ports := range openPorts {
		results, err := me.scanIPPorts(ip, ports)
		if err != nil {
			fmt.Printf("⚠ Nmap scan failed for %s: %v\n", ip, err)
			// 失败时返回基础结果
			for _, port := range ports {
				allResults = append(allResults, &PortScanResult{
					IP:       ip,
					Port:     port,
					Protocol: "tcp",
					Open:     true,
					Service:  "unknown",
				})
			}
			continue
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// scanIPPorts 使用 Nmap 扫描单个 IP 的指定端口
func (me *MasscanEngine) scanIPPorts(ip string, ports []int) ([]*PortScanResult, error) {
	// 构建端口列表
	portStrs := make([]string, len(ports))
	for i, port := range ports {
		portStrs[i] = strconv.Itoa(port)
	}
	portList := strings.Join(portStrs, ",")

	// 使用 Nmap 进行详细扫描
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		nmap.WithPorts(portList),
		nmap.WithServiceInfo(),                         // 服务识别
		nmap.WithVersionIntensity(5),                   // 版本探测强度
		nmap.WithTimingTemplate(nmap.TimingAggressive), // 快速模式
	)
	if err != nil {
		return nil, err
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, err
	}

	if warnings != nil && len(warnings) > 0 {
		fmt.Printf("⚠ Nmap warnings for %s: %v\n", ip, warnings)
	}

	// 解析 Nmap 结果
	var scanResults []*PortScanResult
	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			// 构建服务和版本信息
			service := port.Service.Name
			if service == "" {
				service = "unknown"
			}

			banner := fmt.Sprintf("%s %s", port.Service.Product, port.Service.Version)
			if port.Service.ExtraInfo != "" {
				banner = fmt.Sprintf("%s (%s)", banner, port.Service.ExtraInfo)
			}

			scanResult := &PortScanResult{
				IP:       ip,
				Port:     int(port.ID),
				Protocol: port.Protocol,
				Open:     true,
				Service:  service,
				Banner:   strings.TrimSpace(banner),
			}

			scanResults = append(scanResults, scanResult)
		}
	}

	return scanResults, nil
}

// convertMasscanResults 将 Masscan 结果转换为标准格式（当 Nmap 不可用时）
func (me *MasscanEngine) convertMasscanResults(openPorts map[string][]int) []*PortScanResult {
	var results []*PortScanResult

	for ip, ports := range openPorts {
		for _, port := range ports {
			results = append(results, &PortScanResult{
				IP:       ip,
				Port:     port,
				Protocol: "tcp",
				Open:     true,
				Service:  "unknown",
			})
		}
	}

	return results
}

// GetEngineInfo 获取引擎信息
func (me *MasscanEngine) GetEngineInfo() string {
	info := fmt.Sprintf("Masscan Engine (rate: %d pps)", me.rate)
	if me.nmapAvailable {
		info += " + Nmap Enumeration"
	}
	return info
}

// isAvailable 检查 Masscan 和 Nmap 是否都可用
func (me *MasscanEngine) isAvailable() bool {
	return isMasscanAvailable() && me.isNmapAvailable()
}

// isNmapAvailable 检测 Nmap 是否可用
func (me *MasscanEngine) isNmapAvailable() bool {
	cmd := exec.Command("nmap", "--version")
	if err := cmd.Run(); err != nil {
		fmt.Println("===========nmap======")
		fmt.Println(err.Error())
		fmt.Println("===========nmap======")

		return false
	}
	return true
}
