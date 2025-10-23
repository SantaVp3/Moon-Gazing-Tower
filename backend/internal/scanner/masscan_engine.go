package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
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
	cmd := exec.Command("masscan", "--version")
	if err := cmd.Run(); err != nil {
		return false
	}
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

	cmd := exec.Command("masscan", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("masscan execution failed: %w", err)
	}

	// 解析 Masscan JSON 输出
	return me.parseMasscanOutput(output)
}

// buildPortRanges 构建端口范围字符串
func (me *MasscanEngine) buildPortRanges(ports []int) string {
	if len(ports) == 0 {
		return "1-65535" // 扫描所有端口
	}

	// 将端口列表转换为字符串
	portStrs := make([]string, len(ports))
	for i, port := range ports {
		portStrs[i] = strconv.Itoa(port)
	}

	return strings.Join(portStrs, ",")
}

// parseMasscanOutput 解析 Masscan JSON 输出
func (me *MasscanEngine) parseMasscanOutput(output []byte) (map[string][]int, error) {
	openPorts := make(map[string][]int)

	// Masscan 输出多个 JSON 对象，每行一个
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var result MasscanResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue // 跳过解析错误的行
		}

		// 只处理开放的端口
		if result.Status == "open" {
			if _, exists := openPorts[result.IP]; !exists {
				openPorts[result.IP] = []int{}
			}
			openPorts[result.IP] = append(openPorts[result.IP], result.Port)
		}
	}

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
		return false
	}
	return true
}
