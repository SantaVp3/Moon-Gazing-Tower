package config

import (
	"log"
	"os"
	"strconv"

	"github.com/spf13/viper"
)

// Config 全局配置
type Config struct {
	Server     ServerConfig
	JWT        JWTConfig
	Encryption EncryptionConfig
	Database   DatabaseConfig
	Redis      RedisConfig
	Scanner    ScannerConfig
	Logging    LoggingConfig
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port string
	Mode string
}

// JWTConfig JWT配置
type JWTConfig struct {
	Secret string
}

// EncryptionConfig 加密配置
type EncryptionConfig struct {
	Key string
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host         string
	Port         int
	User         string
	Password     string
	DBName       string
	SSLMode      string
	MaxIdleConns int
	MaxOpenConns int
}

// RedisConfig Redis配置
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// ScannerConfig 扫描器配置
type ScannerConfig struct {
	MaxConcurrentTasks int
	Timeout            int
	MaxRetries         int
	PortScanTimeout    int
	PortScanThreads    int
	DomainBruteThreads int
	DomainDictPath     string
	ScreenshotTimeout  int
	ScreenshotDir      string
	ResultsDir         string
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level      string
	File       string
	MaxSize    int
	MaxBackups int
	MaxAge     int
}

var GlobalConfig *Config

// LoadConfig 加载配置
func LoadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// 读取环境变量
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Failed to read config file: %v", err)
		setDefaults()
	}

	GlobalConfig = &Config{
		Server: ServerConfig{
			Port: getEnvOrConfig("SERVER_PORT", viper.GetString("server.port")),
			Mode: getEnvOrConfig("GIN_MODE", viper.GetString("server.mode")),
		},
		JWT: JWTConfig{
			Secret: getEnvOrConfig("JWT_SECRET", viper.GetString("jwt.secret")),
		},
		Encryption: EncryptionConfig{
			Key: getEnvOrConfig("ENCRYPTION_KEY", viper.GetString("encryption.key")),
		},
		Database: DatabaseConfig{
			Host:         getEnvOrConfig("DB_HOST", viper.GetString("database.host")),
			Port:         getEnvOrConfigInt("DB_PORT", viper.GetInt("database.port")),
			User:         getEnvOrConfig("DB_USER", viper.GetString("database.user")),
			Password:     getEnvOrConfig("DB_PASSWORD", viper.GetString("database.password")),
			DBName:       getEnvOrConfig("DB_NAME", viper.GetString("database.dbname")),
			SSLMode:      viper.GetString("database.sslmode"),
			MaxIdleConns: viper.GetInt("database.max_idle_conns"),
			MaxOpenConns: viper.GetInt("database.max_open_conns"),
		},
		Redis: RedisConfig{
			Host:     getEnvOrConfig("REDIS_HOST", viper.GetString("redis.host")),
			Port:     getEnvOrConfigInt("REDIS_PORT", viper.GetInt("redis.port")),
			Password: getEnvOrConfig("REDIS_PASSWORD", viper.GetString("redis.password")),
			DB:       viper.GetInt("redis.db"),
		},
		Scanner: ScannerConfig{
			MaxConcurrentTasks: viper.GetInt("scanner.max_concurrent_tasks"),
			Timeout:            viper.GetInt("scanner.timeout"),
			MaxRetries:         viper.GetInt("scanner.max_retries"),
			PortScanTimeout:    viper.GetInt("scanner.port_scan_timeout"),
			PortScanThreads:    viper.GetInt("scanner.port_scan_threads"),
			DomainBruteThreads: viper.GetInt("scanner.domain_brute_threads"),
			DomainDictPath:     viper.GetString("scanner.domain_dict_path"),
			ScreenshotTimeout:  viper.GetInt("scanner.screenshot_timeout"),
			ScreenshotDir:      viper.GetString("scanner.screenshot_dir"),
			ResultsDir:         viper.GetString("scanner.results_dir"),
		},
		Logging: LoggingConfig{
			Level:      viper.GetString("logging.level"),
			File:       viper.GetString("logging.file"),
			MaxSize:    viper.GetInt("logging.max_size"),
			MaxBackups: viper.GetInt("logging.max_backups"),
			MaxAge:     viper.GetInt("logging.max_age"),
		},
	}

	return nil
}

// setDefaults 设置默认配置
func setDefaults() {
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.mode", "release")
	viper.SetDefault("jwt.secret", "arl_vp3_secret_key_change_in_production")
	viper.SetDefault("encryption.key", "reconmaster-encryption-key-20251")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_idle_conns", 10)
	viper.SetDefault("database.max_open_conns", 100)
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("scanner.max_concurrent_tasks", 10)
	viper.SetDefault("scanner.timeout", 3600)
	viper.SetDefault("scanner.max_retries", 3)
	viper.SetDefault("scanner.port_scan_timeout", 300)
	viper.SetDefault("scanner.port_scan_threads", 100)
	viper.SetDefault("scanner.domain_brute_threads", 50)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.max_size", 100)
	viper.SetDefault("logging.max_backups", 10)
	viper.SetDefault("logging.max_age", 30)
}

// getEnvOrConfig 从环境变量或配置文件获取值
func getEnvOrConfig(envKey, configValue string) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return configValue
}

// getEnvOrConfigInt 从环境变量或配置文件获取整数值
func getEnvOrConfigInt(envKey string, configValue int) int {
	if value := os.Getenv(envKey); value != "" {
		// 尝试将环境变量转换为整数
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
		// 如果转换失败，使用配置文件的值
		log.Printf("Warning: Failed to parse env var %s as int, using config value", envKey)
	}
	return configValue
}
