package scanner

import (
	"crypto/md5"
	"fmt"
	"sync"
)

// DeduplicationCache 去重缓存
type DeduplicationCache struct {
	cache map[string]bool
	mu    sync.RWMutex
}

// NewDeduplicationCache 创建去重缓存
func NewDeduplicationCache() *DeduplicationCache {
	return &DeduplicationCache{
		cache: make(map[string]bool),
	}
}

// Add 添加记录（返回true表示新记录，false表示重复）
func (dc *DeduplicationCache) Add(key string) bool {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	if dc.cache[key] {
		return false // 已存在
	}
	
	dc.cache[key] = true
	return true // 新记录
}

// Exists 检查是否存在
func (dc *DeduplicationCache) Exists(key string) bool {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	
	return dc.cache[key]
}

// Clear 清空缓存
func (dc *DeduplicationCache) Clear() {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	dc.cache = make(map[string]bool)
}

// Size 获取缓存大小
func (dc *DeduplicationCache) Size() int {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	
	return len(dc.cache)
}

// GenerateDomainKey 生成域名去重键
func GenerateDomainKey(taskID, domain string) string {
	return fmt.Sprintf("%s:%s", taskID, domain)
}

// GenerateIPKey 生成IP去重键
func GenerateIPKey(taskID, ip string) string {
	return fmt.Sprintf("%s:%s", taskID, ip)
}

// GeneratePortKey 生成端口去重键
func GeneratePortKey(taskID, ip string, port int) string {
	return fmt.Sprintf("%s:%s:%d", taskID, ip, port)
}

// GenerateSiteKey 生成站点去重键（基于URL）
func GenerateSiteKey(taskID, url string) string {
	return fmt.Sprintf("%s:%s", taskID, url)
}

// GenerateContentHash 生成内容哈希（用于去重相似内容）
func GenerateContentHash(content string) string {
	hash := md5.Sum([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// ValidateDomain 验证域名格式
func ValidateDomain(domain string) bool {
	if domain == "" {
		return false
	}
	
	// 基本长度检查
	if len(domain) > 253 {
		return false
	}
	
	// 检查是否包含非法字符
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '.' || char == '-') {
			return false
		}
	}
	
	return true
}

// ValidateIP 验证IP格式（简单检查）
func ValidateIP(ip string) bool {
	if ip == "" {
		return false
	}
	
	// 简单验证：长度和字符
	if len(ip) < 7 || len(ip) > 15 {
		return false
	}
	
	parts := 0
	for _, char := range ip {
		if char == '.' {
			parts++
		} else if !(char >= '0' && char <= '9') {
			return false
		}
	}
	
	return parts == 3
}

// ValidatePort 验证端口范围
func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

// ValidateURL 验证URL格式（简单检查）
func ValidateURL(url string) bool {
	if url == "" {
		return false
	}
	
	// 检查是否以http://或https://开头
	if len(url) < 10 {
		return false
	}
	
	if url[:7] != "http://" && url[:8] != "https://" {
		return false
	}
	
	return true
}

