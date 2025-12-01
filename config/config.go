package config

import (
	"log"
	"sync"

	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	JWT        JWTConfig        `mapstructure:"jwt"`
	MongoDB    MongoDBConfig    `mapstructure:"mongodb"`
	Redis      RedisConfig      `mapstructure:"redis"`
	Scanner    ScannerConfig    `mapstructure:"scanner"`
	Log        LogConfig        `mapstructure:"log"`
	Alert      AlertConfig      `mapstructure:"alert"`
	ThirdParty ThirdPartyConfig `mapstructure:"thirdparty"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

type JWTConfig struct {
	Secret string `mapstructure:"secret"`
	Expire int    `mapstructure:"expire"`
	Issuer string `mapstructure:"issuer"`
}

type MongoDBConfig struct {
	URI      string `mapstructure:"uri"`
	Database string `mapstructure:"database"`
	Timeout  int    `mapstructure:"timeout"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type ScannerConfig struct {
	WorkerCount int `mapstructure:"worker_count"`
	Timeout     int `mapstructure:"timeout"`
	RetryCount  int `mapstructure:"retry_count"`
	RetryDelay  int `mapstructure:"retry_delay"`
}

type LogConfig struct {
	Level      string `mapstructure:"level"`
	File       string `mapstructure:"file"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
}

type AlertConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Types   []string `mapstructure:"types"`
}

type ThirdPartyConfig struct {
	Fofa   FofaConfig   `mapstructure:"fofa"`
	Hunter HunterConfig `mapstructure:"hunter"`
	Quake  QuakeConfig  `mapstructure:"quake"`
}

type FofaConfig struct {
	Email string `mapstructure:"email"`
	Key   string `mapstructure:"key"`
}

type HunterConfig struct {
	Key string `mapstructure:"key"`
}

type QuakeConfig struct {
	Key string `mapstructure:"key"`
}

var (
	cfg  *Config
	once sync.Once
)

func LoadConfig(path string) *Config {
	once.Do(func() {
		viper.SetConfigFile(path)
		viper.SetConfigType("yaml")

		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}

		cfg = &Config{}
		if err := viper.Unmarshal(cfg); err != nil {
			log.Fatalf("Failed to unmarshal config: %v", err)
		}
	})

	return cfg
}

func GetConfig() *Config {
	if cfg == nil {
		log.Fatal("Config not loaded. Call LoadConfig first.")
	}
	return cfg
}
