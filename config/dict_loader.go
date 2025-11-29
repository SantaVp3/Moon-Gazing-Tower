package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// DictConfig holds all dictionary configurations
type DictConfig struct {
	Subdomains     []string
	Directories    []string
	Fingerprints   *FingerprintConfig
	CDN            *CDNConfig
	Vuln           *VulnConfig
}

// FingerprintConfig holds fingerprint rules
type FingerprintConfig struct {
	HeaderRules   []FingerprintRuleConfig `yaml:"header_rules"`
	BodyRules     []FingerprintRuleConfig `yaml:"body_rules"`
	TitleRules    []FingerprintRuleConfig `yaml:"title_rules"`
	CookieRules   []FingerprintRuleConfig `yaml:"cookie_rules"`
	IconHashRules []FingerprintRuleConfig `yaml:"icon_hash_rules"`
}

// FingerprintRuleConfig represents a single fingerprint rule
type FingerprintRuleConfig struct {
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
	Pattern  string `yaml:"pattern"`
	Method   string `yaml:"method"`
	Hash     string `yaml:"hash,omitempty"`
}

// CDNConfig holds CDN detection configuration
type CDNConfig struct {
	CNAMEPatterns  map[string]string              `yaml:"cname_patterns"`
	HeaderPatterns map[string]string              `yaml:"header_patterns"`
	IPRanges       map[string][]string            `yaml:"ip_ranges"`
}

// VulnConfig holds vulnerability scanning configuration
type VulnConfig struct {
	SensitivePaths    []SensitivePathConfig   `yaml:"sensitive_paths"`
	WeakPasswords     WeakPasswordConfig      `yaml:"weak_passwords"`
	SensitivePatterns []SensitivePatternConfig `yaml:"sensitive_patterns"`
	BackupExtensions  []string                `yaml:"backup_extensions"`
}

// SensitivePathConfig represents a sensitive path
type SensitivePathConfig struct {
	Path        string `yaml:"path"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

// WeakPasswordConfig holds weak password lists
type WeakPasswordConfig struct {
	Common             []string               `yaml:"common"`
	DefaultCredentials []CredentialConfig     `yaml:"default_credentials"`
	Services           map[string][]CredentialConfig `yaml:"services"`
}

// CredentialConfig represents a username/password pair
type CredentialConfig struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password"`
}

// SensitivePatternConfig represents a sensitive data pattern
type SensitivePatternConfig struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
}

var (
	dictConfig     *DictConfig
	dictConfigOnce sync.Once
	dictBasePath   string
)

// SetDictBasePath sets the base path for dictionary files
func SetDictBasePath(path string) {
	dictBasePath = path
}

// GetDictBasePath returns the base path for dictionary files
func GetDictBasePath() string {
	if dictBasePath == "" {
		// Default to config/dicts relative to current directory
		dictBasePath = "config/dicts"
	}
	return dictBasePath
}

// LoadDictConfig loads all dictionary configurations
func LoadDictConfig() *DictConfig {
	dictConfigOnce.Do(func() {
		dictConfig = &DictConfig{}
		basePath := GetDictBasePath()

		// Load subdomains
		dictConfig.Subdomains = loadTextList(filepath.Join(basePath, "subdomains.txt"))

		// Load directories
		dictConfig.Directories = loadTextList(filepath.Join(basePath, "directories.txt"))

		// Load fingerprints
		dictConfig.Fingerprints = loadFingerprintConfig(filepath.Join(basePath, "fingerprints.yaml"))

		// Load CDN config
		dictConfig.CDN = loadCDNConfig(filepath.Join(basePath, "cdn.yaml"))

		// Load vuln config
		dictConfig.Vuln = loadVulnConfig(filepath.Join(basePath, "vuln.yaml"))
	})

	return dictConfig
}

// GetDictConfig returns the loaded dictionary configuration
func GetDictConfig() *DictConfig {
	if dictConfig == nil {
		return LoadDictConfig()
	}
	return dictConfig
}

// loadTextList loads a text file with one item per line
func loadTextList(filePath string) []string {
	var result []string

	file, err := os.Open(filePath)
	if err != nil {
		// Return empty list if file not found
		return result
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}

	return result
}

// loadFingerprintConfig loads fingerprint configuration from YAML
func loadFingerprintConfig(filePath string) *FingerprintConfig {
	config := &FingerprintConfig{}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return config
	}

	yaml.Unmarshal(data, config)
	return config
}

// loadCDNConfig loads CDN configuration from YAML
func loadCDNConfig(filePath string) *CDNConfig {
	config := &CDNConfig{}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return config
	}

	yaml.Unmarshal(data, config)
	return config
}

// loadVulnConfig loads vulnerability configuration from YAML
func loadVulnConfig(filePath string) *VulnConfig {
	config := &VulnConfig{}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return config
	}

	yaml.Unmarshal(data, config)
	return config
}

// ReloadDictConfig forces reload of dictionary configurations
func ReloadDictConfig() *DictConfig {
	dictConfigOnce = sync.Once{}
	dictConfig = nil
	return LoadDictConfig()
}

// GetSubdomains returns the subdomain wordlist
func GetSubdomains() []string {
	return GetDictConfig().Subdomains
}

// GetDirectories returns the directory wordlist
func GetDirectories() []string {
	return GetDictConfig().Directories
}

// GetFingerprintRules returns fingerprint rules
func GetFingerprintRules() *FingerprintConfig {
	return GetDictConfig().Fingerprints
}

// GetCDNConfig returns CDN detection config
func GetCDNConfig() *CDNConfig {
	return GetDictConfig().CDN
}

// GetVulnConfig returns vulnerability config
func GetVulnConfig() *VulnConfig {
	return GetDictConfig().Vuln
}

// GetWeakPasswords returns common weak passwords
func GetWeakPasswords() []string {
	vulnConfig := GetVulnConfig()
	if vulnConfig != nil && len(vulnConfig.WeakPasswords.Common) > 0 {
		return vulnConfig.WeakPasswords.Common
	}
	return nil
}

// GetDefaultCredentials returns default username/password pairs
func GetDefaultCredentials() []CredentialConfig {
	vulnConfig := GetVulnConfig()
	if vulnConfig != nil && len(vulnConfig.WeakPasswords.DefaultCredentials) > 0 {
		return vulnConfig.WeakPasswords.DefaultCredentials
	}
	return nil
}

// GetServiceCredentials returns credentials for a specific service
func GetServiceCredentials(service string) []CredentialConfig {
	vulnConfig := GetVulnConfig()
	if vulnConfig != nil && vulnConfig.WeakPasswords.Services != nil {
		if creds, ok := vulnConfig.WeakPasswords.Services[service]; ok {
			return creds
		}
	}
	return nil
}

// GetSensitivePaths returns sensitive file paths
func GetSensitivePaths() []SensitivePathConfig {
	vulnConfig := GetVulnConfig()
	if vulnConfig != nil {
		return vulnConfig.SensitivePaths
	}
	return nil
}

// GetBackupExtensions returns backup file extensions
func GetBackupExtensions() []string {
	vulnConfig := GetVulnConfig()
	if vulnConfig != nil && len(vulnConfig.BackupExtensions) > 0 {
		return vulnConfig.BackupExtensions
	}
	return []string{".bak", ".backup", ".old", ".sql", ".zip", ".tar.gz"}
}
