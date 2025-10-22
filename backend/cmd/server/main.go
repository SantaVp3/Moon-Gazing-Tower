package main

import (
	"log"

	"github.com/reconmaster/backend/internal/api"
	"github.com/reconmaster/backend/internal/auth"
	"github.com/reconmaster/backend/internal/cache"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/scheduler"
	"github.com/reconmaster/backend/internal/services"
)

func main() {
	// 加载全局配置
	if err := config.LoadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化JWT配置
	auth.Init()

	// 初始化数据库
	dbConfig := database.Config{
		Host:         config.GlobalConfig.Database.Host,
		Port:         config.GlobalConfig.Database.Port,
		User:         config.GlobalConfig.Database.User,
		Password:     config.GlobalConfig.Database.Password,
		DBName:       config.GlobalConfig.Database.DBName,
		SSLMode:      config.GlobalConfig.Database.SSLMode,
		MaxIdleConns: config.GlobalConfig.Database.MaxIdleConns,
		MaxOpenConns: config.GlobalConfig.Database.MaxOpenConns,
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
		Host:     config.GlobalConfig.Redis.Host,
		Port:     config.GlobalConfig.Redis.Port,
		Password: config.GlobalConfig.Redis.Password,
		DB:       config.GlobalConfig.Redis.DB,
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
	port := config.GlobalConfig.Server.Port
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting ARL_Vp3 server on port %s...", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
