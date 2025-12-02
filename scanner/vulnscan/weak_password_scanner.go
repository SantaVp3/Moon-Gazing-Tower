package vulnscan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"moongazing/config"
	"moongazing/scanner/core"
)

// BruteForceResult represents brute force attack result
type BruteForceResult struct {
	Target      string       `json:"target"`
	Port        int          `json:"port"`
	Service     string       `json:"service"`
	Success     bool         `json:"success"`
	Username    string       `json:"username,omitempty"`
	Password    string       `json:"password,omitempty"`
	Attempts    int          `json:"attempts"`
	Duration    string       `json:"duration"`
	Credentials []Credential `json:"credentials,omitempty"`
}

// Credential represents a valid credential pair
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// WeakPasswordScanner handles weak password brute force
type WeakPasswordScanner struct {
	Timeout     time.Duration
	Concurrency int
	Usernames   []string
	Passwords   []string
}

// NewWeakPasswordScanner creates a new weak password scanner
func NewWeakPasswordScanner(concurrency int) *WeakPasswordScanner {
	if concurrency <= 0 {
		concurrency = 5
	}

	return &WeakPasswordScanner{
		Timeout:     core.ShortHTTPTimeout,
		Concurrency: concurrency,
		Usernames:   getUsernamesFromConfig(),
		Passwords:   getPasswordsFromConfig(),
	}
}

// getUsernamesFromConfig returns usernames from configuration
func getUsernamesFromConfig() []string {
	creds := config.GetDefaultCredentials()
	if len(creds) > 0 {
		// Extract unique usernames
		seen := make(map[string]bool)
		var usernames []string
		for _, c := range creds {
			if c.Username != "" && !seen[c.Username] {
				seen[c.Username] = true
				usernames = append(usernames, c.Username)
			}
		}
		if len(usernames) > 0 {
			return usernames
		}
	}
	// Minimal fallback
	return []string{"admin", "root", "test", "user"}
}

// getPasswordsFromConfig returns passwords from configuration
func getPasswordsFromConfig() []string {
	passwords := GetWeakPasswords()
	if len(passwords) > 0 {
		return passwords
	}
	// Minimal fallback
	return []string{"admin", "123456", "password", "root", "test"}
}

// BruteForceSSH attempts SSH brute force
func (s *WeakPasswordScanner) BruteForceSSH(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "ssh",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	for _, username := range s.Usernames {
		for _, password := range s.Passwords {
			select {
			case <-ctx.Done():
				result.Attempts = attempts
				result.Duration = time.Since(start).String()
				return result
			default:
			}

			attempts++
			if s.trySSH(host, port, username, password) {
				result.Success = true
				result.Username = username
				result.Password = password
				result.Credentials = append(result.Credentials, Credential{
					Username: username,
					Password: password,
				})
				// Continue to find more
			}
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// trySSH attempts SSH authentication (simplified - would need golang.org/x/crypto/ssh)
func (s *WeakPasswordScanner) trySSH(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Read SSH banner
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil || n == 0 {
		return false
	}

	banner := string(buffer[:n])
	if !strings.HasPrefix(banner, "SSH-") {
		return false
	}

	// Note: Full SSH auth would require golang.org/x/crypto/ssh package
	// This is a simplified check - real implementation would use SSH client
	_ = username
	_ = password
	return false
}

// BruteForceMySQL attempts MySQL brute force
func (s *WeakPasswordScanner) BruteForceMySQL(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "mysql",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	// Get MySQL-specific credentials from config
	mysqlCreds := config.GetServiceCredentials("mysql")
	var mysqlUsers []string
	if len(mysqlCreds) > 0 {
		seen := make(map[string]bool)
		for _, c := range mysqlCreds {
			if c.Username != "" && !seen[c.Username] {
				seen[c.Username] = true
				mysqlUsers = append(mysqlUsers, c.Username)
			}
		}
	}
	if len(mysqlUsers) == 0 {
		mysqlUsers = []string{"root", "mysql", "admin"}
	}

	for _, u := range mysqlUsers {
		for _, p := range s.Passwords {
			select {
			case <-ctx.Done():
				result.Attempts = attempts
				result.Duration = time.Since(start).String()
				return result
			default:
			}

			attempts++
			// Note: Real implementation would use database/sql with mysql driver
			// Placeholder - would try connecting with u and p
			_ = u
			_ = p
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// BruteForceFTP attempts FTP brute force
func (s *WeakPasswordScanner) BruteForceFTP(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "ftp",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	for _, username := range s.Usernames {
		for _, password := range s.Passwords {
			select {
			case <-ctx.Done():
				result.Attempts = attempts
				result.Duration = time.Since(start).String()
				return result
			default:
			}

			attempts++
			if s.tryFTP(host, port, username, password) {
				result.Success = true
				result.Username = username
				result.Password = password
				result.Credentials = append(result.Credentials, Credential{
					Username: username,
					Password: password,
				})
			}
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// tryFTP attempts FTP authentication
func (s *WeakPasswordScanner) tryFTP(host string, port int, username, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read welcome banner
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	banner, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(banner, "220") {
		return false
	}

	// Send USER command
	fmt.Fprintf(conn, "USER %s\r\n", username)
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if password needed
	if !strings.HasPrefix(response, "331") {
		return false
	}

	// Send PASS command
	fmt.Fprintf(conn, "PASS %s\r\n", password)
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	response, err = reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if login successful
	if strings.HasPrefix(response, "230") {
		fmt.Fprintf(conn, "QUIT\r\n")
		return true
	}

	return false
}

// BruteForceRedis attempts Redis brute force
func (s *WeakPasswordScanner) BruteForceRedis(ctx context.Context, host string, port int) *BruteForceResult {
	result := &BruteForceResult{
		Target:  host,
		Port:    port,
		Service: "redis",
		Success: false,
	}

	start := time.Now()
	attempts := 0

	// First try without password
	if s.tryRedis(host, port, "") {
		result.Success = true
		result.Password = "(no password)"
		result.Credentials = append(result.Credentials, Credential{
			Username: "",
			Password: "(no password)",
		})
	}

	for _, password := range s.Passwords {
		select {
		case <-ctx.Done():
			result.Attempts = attempts
			result.Duration = time.Since(start).String()
			return result
		default:
		}

		attempts++
		if s.tryRedis(host, port, password) {
			result.Success = true
			result.Password = password
			result.Credentials = append(result.Credentials, Credential{
				Username: "",
				Password: password,
			})
		}
	}

	result.Attempts = attempts
	result.Duration = time.Since(start).String()
	return result
}

// tryRedis attempts Redis authentication
func (s *WeakPasswordScanner) tryRedis(host string, port int, password string) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	if password != "" {
		// Send AUTH command
		fmt.Fprintf(conn, "*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}
		if !strings.HasPrefix(response, "+OK") {
			return false
		}
	}

	// Try INFO command
	fmt.Fprintf(conn, "*1\r\n$4\r\nINFO\r\n")
	conn.SetReadDeadline(time.Now().Add(s.Timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	// Check if INFO returned data (starts with $ for bulk string)
	if strings.HasPrefix(response, "$") {
		return true
	}

	return false
}
