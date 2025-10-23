package database

import (
	"fmt"
	"log"

	"gorm.io/gorm"
)

// MigratePoCFields 迁移 PoC 表字段长度
func MigratePoCFields(db *gorm.DB) error {
	log.Println("🔧 开始迁移 PoC 表字段...")

	// 根据不同数据库执行不同的 SQL
	// PostgreSQL
	sqlCommands := []string{
		// 扩展 Tags 字段长度
		"ALTER TABLE pocs ALTER COLUMN tags TYPE varchar(500)",
		// 扩展 Fingerprints 字段长度（如果还没有）
		"ALTER TABLE pocs ALTER COLUMN fingerprints TYPE varchar(1000)",
		// 扩展 AppNames 字段长度（如果还没有）
		"ALTER TABLE pocs ALTER COLUMN app_names TYPE varchar(1000)",
		// 扩展 Category 字段长度（防止一些特殊分类太长）
		"ALTER TABLE pocs ALTER COLUMN category TYPE varchar(200)",
		// 扩展 CVE 字段长度（一些 CVE 可能带额外信息）
		"ALTER TABLE pocs ALTER COLUMN cve TYPE varchar(100)",
		// 扩展 Severity 字段长度
		"ALTER TABLE pocs ALTER COLUMN severity TYPE varchar(100)",
		// 扩展 PoCType 字段长度
		"ALTER TABLE pocs ALTER COLUMN poc_type TYPE varchar(100)",
	}

	for _, sql := range sqlCommands {
		if err := db.Exec(sql).Error; err != nil {
			// 如果字段已经是正确的类型，会报错，但可以忽略
			log.Printf("⚠️  SQL 执行警告（可忽略）: %v\n   SQL: %s", err, sql)
		} else {
			log.Printf("✅ 执行成功: %s", sql)
		}
	}

	log.Println("✅ PoC 表字段迁移完成")
	return nil
}

// MigratePoCFieldsSQLite SQLite 版本的迁移
func MigratePoCFieldsSQLite(db *gorm.DB) error {
	log.Println("🔧 开始迁移 PoC 表字段 (SQLite)...")

	// SQLite 不支持 ALTER COLUMN，需要重建表
	// 但是由于我们使用 AutoMigrate，GORM 会自动处理
	log.Println("ℹ️  SQLite 使用 AutoMigrate 自动处理字段长度")

	return nil
}

// ApplyPoCFieldsMigration 应用 PoC 字段迁移（自动检测数据库类型）
func ApplyPoCFieldsMigration(db *gorm.DB) error {
	// 检测数据库类型
	dbName := db.Dialector.Name()

	fmt.Printf("📊 数据库类型: %s\n", dbName)

	switch dbName {
	case "postgres":
		return MigratePoCFields(db)
	case "sqlite":
		return MigratePoCFieldsSQLite(db)
	default:
		log.Printf("⚠️  未知数据库类型: %s，跳过字段迁移", dbName)
		return nil
	}
}
