package main

import (
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// 初始化管理员账号
func main() {
	// 加载全局配置
	if err := config.LoadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

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

	// 检查是否已存在管理员
	var count int64
	database.DB.Model(&models.User{}).Where("role = ?", "admin").Count(&count)
	if count > 0 {
		log.Println("Admin user already exists")
		return
	}

	// 创建管理员账号
	admin := models.User{
		ID:       uuid.New().String(),
		Username: "admin",
		Email:    "admin@arl.local",
		Nickname: "系统管理员",
		Role:     "admin",
		Status:   "active",
	}

	// 默认密码: arlpass
	if err := admin.SetPassword("arlpass"); err != nil {
		log.Fatalf("Failed to set password: %v", err)
	}

	if err := database.DB.Create(&admin).Error; err != nil {
		log.Fatalf("Failed to create admin: %v", err)
	}

	fmt.Println("==========================================")
	fmt.Println("Admin account created successfully!")
	fmt.Println("==========================================")
	fmt.Println("Username: admin")
	fmt.Println("Password: arlpass")
	fmt.Println("==========================================")
	fmt.Println("Please change the password after first login!")
	fmt.Println("==========================================")
}
