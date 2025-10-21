package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// GenerateID 生成随机ID
func GenerateID(prefix string) string {
	timestamp := time.Now().Unix()
	random := rand.Intn(100000)
	return fmt.Sprintf("%s_%d_%d", prefix, timestamp, random)
}

// MD5Hash 计算MD5哈希
func MD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// SHA256Hash 计算SHA256哈希
func SHA256Hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

// IsPrivateIP 判断是否为内网IP
func IsPrivateIP(ip string) bool {
	// 10.0.0.0/8
	if strings.HasPrefix(ip, "10.") {
		return true
	}
	// 172.16.0.0/12
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			second := parts[1]
			if second >= "16" && second <= "31" {
				return true
			}
		}
	}
	// 192.168.0.0/16
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}
	// 127.0.0.0/8
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	return false
}

// SanitizeFilename 清理文件名
func SanitizeFilename(filename string) string {
	// 移除不安全的字符
	unsafe := []string{"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range unsafe {
		filename = strings.ReplaceAll(filename, char, "_")
	}
	return filename
}

// TruncateString 截断字符串
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// Contains 检查切片是否包含元素
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates 移除重复元素
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// ParseTarget 解析目标
func ParseTarget(target string) ([]string, error) {
	// 分割多个目标
	targets := strings.Split(target, ",")
	var result []string

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// TODO: 支持IP段解析 (192.168.1.0/24)
		// 现在只是简单添加
		result = append(result, t)
	}

	return result, nil
}

// FormatDuration 格式化时间间隔
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f秒", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0f分钟", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f小时", d.Hours())
	}
	return fmt.Sprintf("%.1f天", d.Hours()/24)
}

// GeneratePassword 生成随机密码
func GeneratePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	rand.Seed(time.Now().UnixNano())
	
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// IsValidDomain 验证域名格式
func IsValidDomain(domain string) bool {
	if domain == "" || len(domain) > 255 {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if strings.Contains(domain, " ") {
		return false
	}
	return true
}

// IsValidIP 验证IP格式
func IsValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		// 简单验证，实际应该更严格
	}
	return true
}

// ChunkSlice 将切片分块
func ChunkSlice(slice []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

// MergeMap 合并map
func MergeMap(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}
