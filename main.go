// 望月楼 - Moon Gazing Tower
// 作者: SantaVp3
// 团队: NoSafe

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"moongazing/api"
	"moongazing/config"
	"moongazing/database"
	"moongazing/router"
	"moongazing/service"

	"github.com/gin-gonic/gin"
)

func main() {
	// Get executable directory for config path
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)
	
	// Load configuration
	configPath := filepath.Join(execDir, "..", "config", "config.yaml")
	if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
		configPath = envPath
	}
	// If config not found, try current directory
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "config/config.yaml"
	}
	cfg := config.LoadConfig(configPath)
	
	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)
	
	// Initialize MongoDB
	database.InitMongoDB(&cfg.MongoDB)
	defer database.CloseMongoDB()
	
	// Initialize Redis
	database.InitRedis(&cfg.Redis)
	defer database.CloseRedis()
	
	// Initialize default admin user
	userService := service.NewUserService()
	if err := userService.InitAdmin(); err != nil {
		log.Printf("Warning: Failed to initialize admin user: %v", err)
	}
	
	// Scan POC directory for auto-import
	log.Println("Scanning POC directory...")
	pocService := service.NewPOCService()
	pocDir := filepath.Join(execDir, "..", "pocs")
	if envPocDir := os.Getenv("POC_DIR"); envPocDir != "" {
		pocDir = envPocDir
	}
	// If pocs directory not found at execDir, try current directory
	if _, err := os.Stat(pocDir); os.IsNotExist(err) {
		pocDir = "pocs"
	}
	// Create pocs directory if it doesn't exist
	if _, err := os.Stat(pocDir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(pocDir, 0755); mkErr == nil {
			log.Printf("Created POC directory: %s", pocDir)
		}
	}
	pocService.ScanPOCDirectory(pocDir)
	
	// Start task executor
	log.Println("Starting task executor...")
	taskExecutor := service.NewTaskExecutor(5) // 5 workers
	taskExecutor.Start()
	log.Println("Task executor started")
	defer taskExecutor.Stop()
	
	// Start cruise scheduler
	log.Println("Starting cruise scheduler...")
	cruiseService := service.NewCruiseService()
	if err := cruiseService.Start(); err != nil {
		log.Printf("Warning: Failed to start cruise scheduler: %v", err)
	}
	log.Println("Cruise scheduler started")
	defer cruiseService.Stop()

	// Initialize WebSocket hub for real-time data
	log.Println("Initializing WebSocket hub...")
	wsHub := api.NewHub()
	go wsHub.Run()
	go wsHub.StartMonitorTask()

	// Setup router with WebSocket hub
	r := router.SetupRouterWithWebSocket(wsHub)
	
	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Server starting on %s", addr)
	
	// Graceful shutdown
	go func() {
		if err := r.Run(addr); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()
	
	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Shutting down server...")
}
