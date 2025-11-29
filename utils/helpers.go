package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword checks if the provided password matches the hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// MD5Hash generates MD5 hash of a string
func MD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// SHA256Hash generates SHA256 hash of a string
func SHA256Hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

// GenerateRandomString generates a random string of given length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// IsValidEmail validates email format
func IsValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}

// IsValidIP validates IP address format
func IsValidIP(ip string) bool {
	pattern := `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	matched, _ := regexp.MatchString(pattern, ip)
	return matched
}

// IsValidDomain validates domain format
func IsValidDomain(domain string) bool {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, domain)
	return matched
}

// IsValidURL validates URL format
func IsValidURL(url string) bool {
	pattern := `^https?://[^\s/$.?#].[^\s]*$`
	matched, _ := regexp.MatchString(pattern, strings.ToLower(url))
	return matched
}

// IsValidCIDR validates CIDR format
func IsValidCIDR(cidr string) bool {
	pattern := `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$`
	matched, _ := regexp.MatchString(pattern, cidr)
	return matched
}

// ParsePortRange parses port range string like "1-1000" or "80,443,8080"
func ParsePortRange(portRange string) []int {
	var ports []int
	
	// Handle comma-separated ports
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Range like "1-1000"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var start, end int
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)
				for i := start; i <= end; i++ {
					if i > 0 && i <= 65535 {
						ports = append(ports, i)
					}
				}
			}
		} else {
			// Single port
			var port int
			fmt.Sscanf(part, "%d", &port)
			if port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}
	
	return ports
}

// UniqueStrings removes duplicates from string slice
func UniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range input {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

// ContainsString checks if a slice contains a string
func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// FormatBytes formats bytes to human readable string
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
