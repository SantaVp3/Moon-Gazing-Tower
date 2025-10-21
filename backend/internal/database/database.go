package database

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Config 数据库配置
type Config struct {
	Host         string
	Port         int
	User         string
	Password     string
	DBName       string
	SSLMode      string
	MaxIdleConns int
	MaxOpenConns int
}

// Initialize 初始化数据库连接
func Initialize(config Config) error {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// 设置连接池
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// 自动迁移
	if err := autoMigrate(); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// 注释掉旧的硬编码指纹初始化，改为使用 YAML 文件加载
	// if err := InitDefaultFingerprints(); err != nil {
	// 	log.Printf("Warning: Failed to initialize fingerprints: %v", err)
	// }

	log.Println("Database connected successfully")
	return nil
}

// autoMigrate 自动迁移数据库表
func autoMigrate() error {
	return DB.AutoMigrate(
		&models.User{},
		&models.UserSession{},
		&models.Task{},
		&models.Domain{},
		&models.IP{},
		&models.Port{},
		&models.Site{},
		&models.URL{},
		&models.CrawlerResult{},
		&models.Vulnerability{},
		&models.Monitor{},
		&models.Policy{},
		&models.MonitorResult{},
		&models.AssetGroup{},
		&models.AssetGroupItem{},
		&models.Setting{},
		&models.Dictionary{},
		&models.Fingerprint{},
		&models.PoC{},
		&models.PoCExecutionLog{},
		&models.GitHubMonitor{},
		&models.GitHubMonitorResult{},
		&models.ScheduledTask{},
		&models.ScheduledTaskLog{},
	)
}

// InitDictionaries 初始化字典数据
func InitDictionaries() error {
	// 扫描字典目录
	dictTypes := []string{"domain", "port", "file"}
	
	for _, dictType := range dictTypes {
		dictDir := fmt.Sprintf("./configs/dicts/%s", dictType)
		
		// 检查目录是否存在
		if _, err := os.Stat(dictDir); os.IsNotExist(err) {
			continue
		}
		
		// 读取目录中的文件
		files, err := os.ReadDir(dictDir)
		if err != nil {
			log.Printf("Failed to read dict directory %s: %v", dictDir, err)
			continue
		}
		
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".txt") {
				continue
			}
			
			filePath := fmt.Sprintf("%s/%s", dictDir, file.Name())
			
			// 检查数据库中是否已存在
			var existingDict models.Dictionary
			if err := DB.Where("file_path = ?", filePath).First(&existingDict).Error; err == nil {
				// 已存在，跳过
				continue
			}
			
			// 获取文件信息
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			
			// 统计行数
			lineCount := countFileLines(filePath)
			
			// 生成字典名称（去掉时间戳前缀和.txt后缀）
			name := strings.TrimSuffix(file.Name(), ".txt")
			// 如果文件名以时间戳_开头，去掉时间戳部分
			if idx := strings.Index(name, "_"); idx > 0 && idx < 15 {
				name = name[idx+1:]
			}
			
			// 创建字典记录
			dict := models.Dictionary{
				Name:        name,
				Type:        dictType,
				FilePath:    filePath,
				Size:        fileInfo.Size(),
				LineCount:   lineCount,
				Description: fmt.Sprintf("系统内置%s字典", dictType),
				IsDefault:   file.Name() == "big.txt", // big.txt 设为默认
				CreatedBy:   "system",
			}
			
			if err := DB.Create(&dict).Error; err != nil {
				log.Printf("Failed to create dictionary record for %s: %v", filePath, err)
			} else {
				log.Printf("Initialized dictionary: %s (%d lines)", name, lineCount)
			}
		}
	}
	
	return nil
}

// countFileLines 统计文件行数
func countFileLines(filePath string) int {
	file, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lineCount++
		}
	}
	
	return lineCount
}

// Close 关闭数据库连接
func Close() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
