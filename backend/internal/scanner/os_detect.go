package scanner

import (
	"fmt"
	"net"
	"time"
)

// OSDetector 操作系统检测器
type OSDetector struct {
	timeout time.Duration
}

// NewOSDetector 创建OS检测器
func NewOSDetector() *OSDetector {
	return &OSDetector{
		timeout: 5 * time.Second,
	}
}

// Detect 检测操作系统
func (od *OSDetector) Detect(ip string, openPorts []int) string {
	// 基于开放端口和服务特征推断操作系统
	
	// Windows特征
	windowsScore := 0
	// Linux特征
	linuxScore := 0
	// 其他特征
	otherScore := 0

	for _, port := range openPorts {
		switch port {
		case 135, 139, 445, 3389: // Windows常见端口
			windowsScore += 2
		case 22, 111, 2049: // Linux常见端口
			linuxScore += 2
		case 80, 443, 8080: // 通用端口
			// 不加分
		}
	}

	// 尝试TTL检测
	ttl := od.detectTTL(ip)
	if ttl > 0 {
		if ttl <= 64 {
			linuxScore += 3 // Linux/Unix TTL通常是64
		} else if ttl <= 128 {
			windowsScore += 3 // Windows TTL通常是128
		}
	}

	// 根据分数判断
	if windowsScore > linuxScore && windowsScore > otherScore {
		return "Windows"
	} else if linuxScore > windowsScore && linuxScore > otherScore {
		return "Linux/Unix"
	}

	return "Unknown"
}

// detectTTL 检测TTL值
func (od *OSDetector) detectTTL(ip string) int {
	// 尝试ping来获取TTL
	// 这里简化实现，实际需要使用raw socket或调用系统ping命令
	
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", ip), od.timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()

	// 无法直接获取TTL，这里返回0
	// 实际实现需要使用syscall或解析ping输出
	return 0
}

// DetectByBanner 通过Banner检测OS
func (od *OSDetector) DetectByBanner(banner, service string) string {
	bannerLower := toLower(banner)
	
	// Windows特征
	if contains(bannerLower, "microsoft") ||
		contains(bannerLower, "windows") ||
		contains(bannerLower, "win32") ||
		contains(bannerLower, "iis") {
		return "Windows"
	}

	// Linux特征
	if contains(bannerLower, "linux") ||
		contains(bannerLower, "ubuntu") ||
		contains(bannerLower, "debian") ||
		contains(bannerLower, "centos") ||
		contains(bannerLower, "red hat") ||
		contains(bannerLower, "fedora") {
		return "Linux"
	}

	// Unix特征
	if contains(bannerLower, "unix") ||
		contains(bannerLower, "bsd") ||
		contains(bannerLower, "freebsd") ||
		contains(bannerLower, "openbsd") ||
		contains(bannerLower, "netbsd") {
		return "Unix"
	}

	// Mac特征
	if contains(bannerLower, "darwin") ||
		contains(bannerLower, "mac os") ||
		contains(bannerLower, "macos") {
		return "macOS"
	}

	return ""
}

// contains 字符串包含检测（忽略大小写）
func contains(s, substr string) bool {
	return indexOf(s, substr) >= 0
}

// indexOf 查找子字符串位置
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// toLower 转小写
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}
