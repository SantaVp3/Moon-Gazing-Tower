package main

import (
	"log"
	"os"

	"github.com/reconmaster/backend/internal/api"
	"github.com/reconmaster/backend/internal/cache"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/scheduler"
	"github.com/reconmaster/backend/internal/services"
	"github.com/spf13/viper"
)

func main() {
	// 加载配置
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化数据库
	dbConfig := database.Config{
		Host:         getEnvOrConfig("DB_HOST", viper.GetString("database.host")),
		Port:         getEnvOrConfigInt("DB_PORT", viper.GetInt("database.port")),
		User:         getEnvOrConfig("DB_USER", viper.GetString("database.user")),
		Password:     getEnvOrConfig("DB_PASSWORD", viper.GetString("database.password")),
		DBName:       getEnvOrConfig("DB_NAME", viper.GetString("database.dbname")),
		SSLMode:      viper.GetString("database.sslmode"),
		MaxIdleConns: viper.GetInt("database.max_idle_conns"),
		MaxOpenConns: viper.GetInt("database.max_open_conns"),
	}

	if err := database.Initialize(dbConfig); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	// 初始化字典数据
	if err := database.InitDictionaries(); err != nil {
		log.Printf("Warning: Failed to initialize dictionaries: %v", err)
	}

	// 自动加载默认指纹库（首次启动时）
	fingerprintLoader := services.NewFingerprintLoader()
	if err := fingerprintLoader.LoadDefaultFingerprints(); err != nil {
		log.Printf("Warning: Failed to load default fingerprints: %v", err)
	}

	log.Println("Using smart PoC detection based on fingerprints")

	// 初始化Redis
	redisConfig := cache.Config{
		Host:     getEnvOrConfig("REDIS_HOST", viper.GetString("redis.host")),
		Port:     getEnvOrConfigInt("REDIS_PORT", viper.GetInt("redis.port")),
		Password: getEnvOrConfig("REDIS_PASSWORD", viper.GetString("redis.password")),
		DB:       viper.GetInt("redis.db"),
	}

	if err := cache.Initialize(redisConfig); err != nil {
		log.Fatalf("Failed to initialize redis: %v", err)
	}
	defer cache.Close()

	// 创建任务服务
	taskService := services.NewTaskService()

	// 创建并启动调度器
	scheduler := scheduler.NewScheduler(taskService)
	scheduler.Start()
	defer scheduler.Stop()

	// 设置路由
	router := api.SetupRouter(taskService)

	// 启动服务器
	port := viper.GetString("server.port")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting ARL_Vp3 server on port %s...", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// loadConfig 加载配置文件
func loadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	// 读取环境变量
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Failed to read config file: %v", err)
		// 使用默认配置
		setDefaults()
	}

	return nil
}

// setDefaults 设置默认配置
func setDefaults() {
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
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
		// 简单实现，实际应该处理转换错误
		return configValue
	}
	return configValue
}
