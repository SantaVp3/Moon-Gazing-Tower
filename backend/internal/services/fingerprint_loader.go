package services

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
)

// FingerprintLoader 指纹加载器
type FingerprintLoader struct{}

// NewFingerprintLoader 创建指纹加载器
func NewFingerprintLoader() *FingerprintLoader {
	return &FingerprintLoader{}
}

// LoadDefaultFingerprints 加载默认指纹库（首次启动时）
func (l *FingerprintLoader) LoadDefaultFingerprints() error {
	// 检查是否已经有指纹数据
	var count int64
	database.DB.Model(&models.Fingerprint{}).Count(&count)
	
	if count > 0 {
		fmt.Printf("数据库中已有 %d 条指纹，跳过自动加载\n", count)
		return nil
	}

	fmt.Println("首次启动，开始加载默认指纹库...")

	// 指纹文件路径
	fingerprintFile := "configs/fingerprints/finger.yaml"
	
	// 检查文件是否存在
	if _, err := os.Stat(fingerprintFile); os.IsNotExist(err) {
		fmt.Printf("警告：默认指纹文件不存在: %s\n", fingerprintFile)
		return nil
	}

	// 读取文件
	file, err := os.Open(fingerprintFile)
	if err != nil {
		return fmt.Errorf("failed to open fingerprint file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read fingerprint file: %v", err)
	}

	// 解析 YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	fmt.Printf("成功解析 YAML，共 %d 个指纹定义\n", len(rawData))

	// 转换并导入指纹
	imported, skipped, failed := l.importFingerprints(rawData)

	fmt.Printf("指纹加载完成！成功: %d, 跳过: %d, 失败: %d\n", imported, skipped, failed)
	
	return nil
}

// importFingerprints 导入指纹数据
func (l *FingerprintLoader) importFingerprints(rawData map[string]interface{}) (imported, skipped, failed int) {
	totalFingerprints := len(rawData)
	processedCount := 0
	
	for name, value := range rawData {
		processedCount++
		if processedCount%1000 == 0 {
			fmt.Printf("处理进度: %d/%d (成功:%d, 跳过:%d, 失败:%d)\n", 
				processedCount, totalFingerprints, imported, skipped, failed)
		}
		
		// 跳过空名称
		if name == "" {
			failed++
			continue
		}

		// 解析指纹对象（包含 dsl 字段）
		fpData, ok := value.(map[string]interface{})
		if !ok {
			failed++
			continue
		}

		// 获取 dsl 规则数组
		dslInterface, ok := fpData["dsl"]
		if !ok {
			failed++
			continue
		}

		dslArray, ok := dslInterface.([]interface{})
		if !ok {
			failed++
			continue
		}

		// 转换为字符串数组
		var dslRules []string
		for _, item := range dslArray {
			if str, ok := item.(string); ok {
				dslRules = append(dslRules, str)
			}
		}

		if len(dslRules) == 0 {
			failed++
			continue
		}

		// 检查是否已存在（根据名称去重）
		var existing models.Fingerprint
		err := database.DB.Where("name = ?", name).
			First(&existing).Error

		if err == nil {
			// 已存在，跳过
			skipped++
			continue
		}

		// 创建指纹记录
		fingerprint := &models.Fingerprint{
			Name:        name,
			Category:    "Web", // 默认分类
			DSL:         dslRules,
			Description: fmt.Sprintf("从默认指纹库导入: %s", name),
			IsEnabled:   true,
		}

		// 插入数据库
		if err := database.DB.Create(fingerprint).Error; err != nil {
			// 忽略重复键错误
			if !strings.Contains(err.Error(), "duplicate") && 
			   !strings.Contains(err.Error(), "unique constraint") {
				if failed < 100 {
					fmt.Printf("插入指纹失败: %s - %v\n", name, err)
				}
			}
			failed++
			continue
		}

		imported++
	}

	return
}

// LoadFingerprintsFromFile 从文件加载指纹（供API使用）
func (l *FingerprintLoader) LoadFingerprintsFromFile(filePath string) (imported, skipped, failed int, err error) {
	// 检查文件扩展名
	ext := strings.ToLower(filepath.Ext(filePath))
	
	if ext != ".yaml" && ext != ".yml" {
		return 0, 0, 0, fmt.Errorf("unsupported file format: %s", ext)
	}

	// 读取文件
	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read file: %v", err)
	}

	// 解析 YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to parse YAML: %v", err)
	}

	// 导入指纹
	imported, skipped, failed = l.importFingerprints(rawData)
	
	return imported, skipped, failed, nil
}

