package main

import (
	"fmt"
	"log"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

// 初始化管理员账号
func main() {
	// 加载配置
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化数据库
	dbConfig := database.Config{
		Host:     viper.GetString("database.host"),
		Port:     viper.GetInt("database.port"),
		User:     viper.GetString("database.user"),
		Password: viper.GetString("database.password"),
		DBName:   viper.GetString("database.dbname"),
		SSLMode:  viper.GetString("database.sslmode"),
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

func loadConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath("../../configs")
	viper.AddConfigPath("../configs")

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	return nil
}

