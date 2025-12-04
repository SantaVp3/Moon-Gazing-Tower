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
	Subdomains    []string
	Directories   []string
	Fingerprints  *FingerprintConfig
	CDN           *CDNConfig
	Vuln          *VulnConfig
	Ports         *PortsConfig
	FaviconHashes *FaviconHashConfig
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
	CNAMEPatterns  map[string]string   `yaml:"cname_patterns"`
	HeaderPatterns map[string]string   `yaml:"header_patterns"`
	IPRanges       map[string][]string `yaml:"ip_ranges"`
}

// VulnConfig holds vulnerability scanning configuration
type VulnConfig struct {
	SensitivePaths    []SensitivePathConfig    `yaml:"sensitive_paths"`
	WeakPasswords     WeakPasswordConfig       `yaml:"weak_passwords"`
	SensitivePatterns []SensitivePatternConfig `yaml:"sensitive_patterns"`
	BackupExtensions  []string                 `yaml:"backup_extensions"`
}

// SensitivePathConfig represents a sensitive path
type SensitivePathConfig struct {
	Path        string `yaml:"path"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
}

// WeakPasswordConfig holds weak password lists
type WeakPasswordConfig struct {
	Common             []string                      `yaml:"common"`
	DefaultCredentials []CredentialConfig            `yaml:"default_credentials"`
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

// PortsConfig holds port scanning configuration
type PortsConfig struct {
	CommonPorts    []int          `yaml:"common_ports"`
	TopPorts       []int          `yaml:"top_ports"`
	PortServiceMap map[int]string `yaml:"port_service_map"`
	HTTPPorts      []int          `yaml:"http_ports"`
	NonHTTPPorts   []int          `yaml:"non_http_ports"`
}

// FaviconHashConfig holds favicon hash to product mapping
type FaviconHashConfig struct {
	FaviconHashes map[string]string `yaml:"favicon_hashes"`
	FaviconMD5    map[string]string `yaml:"favicon_md5"`
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
		txtPath := filepath.Join(basePath, "txt")
		yamlPath := filepath.Join(basePath, "yaml")

		// Load subdomains
		dictConfig.Subdomains = loadTextList(filepath.Join(txtPath, "subdomains.txt"))

		// Load directories
		dictConfig.Directories = loadTextList(filepath.Join(txtPath, "directories.txt"))

		// Load fingerprints
		dictConfig.Fingerprints = loadFingerprintConfig(filepath.Join(yamlPath, "fingerprints.yaml"))

		// Load CDN config
		dictConfig.CDN = loadCDNConfig(filepath.Join(yamlPath, "cdn.yaml"))

		// Load vuln config
		dictConfig.Vuln = loadVulnConfig(filepath.Join(yamlPath, "vuln.yaml"))

		// Load ports config
		dictConfig.Ports = loadPortsConfig(filepath.Join(yamlPath, "ports.yaml"))

		// Load favicon hashes
		dictConfig.FaviconHashes = loadFaviconHashConfig(filepath.Join(yamlPath, "favicon_hashes.yaml"))
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

// loadPortsConfig loads port configuration from YAML
func loadPortsConfig(filePath string) *PortsConfig {
	config := &PortsConfig{
		PortServiceMap: make(map[int]string),
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return config
	}

	yaml.Unmarshal(data, config)
	return config
}

// loadFaviconHashConfig loads favicon hash configuration from YAML
func loadFaviconHashConfig(filePath string) *FaviconHashConfig {
	config := &FaviconHashConfig{
		FaviconHashes: make(map[string]string),
		FaviconMD5:    make(map[string]string),
	}

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
	if vulnConfig != nil {
		return vulnConfig.BackupExtensions
	}
	return nil
}

// GetPortsConfig returns port configuration
func GetPortsConfig() *PortsConfig {
	return GetDictConfig().Ports
}

// GetCommonPorts returns common port list
func GetCommonPorts() []int {
	portsConfig := GetPortsConfig()
	if portsConfig != nil {
		return portsConfig.CommonPorts
	}
	return nil
}

// GetTopPorts returns top port list
func GetTopPorts() []int {
	portsConfig := GetPortsConfig()
	if portsConfig != nil {
		return portsConfig.TopPorts
	}
	return nil
}

// GetPortServiceMap returns port to service name mapping
func GetPortServiceMap() map[int]string {
	portsConfig := GetPortsConfig()
	if portsConfig != nil {
		return portsConfig.PortServiceMap
	}
	return nil
}

// GetHTTPPorts returns ports that typically run HTTP services
func GetHTTPPorts() []int {
	portsConfig := GetPortsConfig()
	if portsConfig != nil {
		return portsConfig.HTTPPorts
	}
	return nil
}

// GetNonHTTPPorts returns ports that are definitely not HTTP
func GetNonHTTPPorts() []int {
	portsConfig := GetPortsConfig()
	if portsConfig != nil {
		return portsConfig.NonHTTPPorts
	}
	return nil
}

// IsHTTPPort checks if a port is likely to be HTTP
func IsHTTPPort(port int) bool {
	for _, p := range GetHTTPPorts() {
		if p == port {
			return true
		}
	}
	return false
}

// IsNonHTTPPort checks if a port is definitely not HTTP
func IsNonHTTPPort(port int) bool {
	for _, p := range GetNonHTTPPorts() {
		if p == port {
			return true
		}
	}
	return false
}

// GetFaviconHashConfig returns favicon hash configuration
func GetFaviconHashConfig() *FaviconHashConfig {
	return GetDictConfig().FaviconHashes
}

// GetFaviconHashes returns favicon hash to product mapping
func GetFaviconHashes() map[string]string {
	faviconConfig := GetFaviconHashConfig()
	if faviconConfig != nil && len(faviconConfig.FaviconHashes) > 0 {
		return faviconConfig.FaviconHashes
	}
	return nil
}

// GetFaviconMD5 returns favicon MD5 to product mapping
func GetFaviconMD5() map[string]string {
	faviconConfig := GetFaviconHashConfig()
	if faviconConfig != nil && len(faviconConfig.FaviconMD5) > 0 {
		return faviconConfig.FaviconMD5
	}
	return nil
}
