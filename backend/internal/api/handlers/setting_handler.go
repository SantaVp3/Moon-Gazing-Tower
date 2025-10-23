package handlers

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// SettingHandler 设置处理器
type SettingHandler struct {
	encryptionKey []byte
}

// NewSettingHandler 创建设置处理器
func NewSettingHandler() *SettingHandler {
	// 从配置中获取加密密钥，如果没有则使用默认密钥
	key := config.GlobalConfig.Encryption.Key
	if key == "" {
		key = "reconmaster-encryption-key-20251" // 正好32字节
	}
	return &SettingHandler{
		encryptionKey: []byte(key),
	}
}

// GetSettings 获取所有设置
func (h *SettingHandler) GetSettings(c *gin.Context) {
	category := c.Query("category")

	var settings []models.Setting
	query := database.DB
	if category != "" {
		query = query.Where("category = ?", category)
	}

	if err := query.Find(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get settings"})
		return
	}

	// 解密加密的值
	for i := range settings {
		if settings[i].IsEncrypted && settings[i].Value != "" {
			if decrypted, err := h.decrypt(settings[i].Value); err == nil {
				settings[i].Value = decrypted
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// GetSetting 获取单个设置
func (h *SettingHandler) GetSetting(c *gin.Context) {
	key := c.Param("key")

	var setting models.Setting
	if err := database.DB.Where("key = ?", key).First(&setting).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Setting not found"})
		return
	}

	// 解密加密的值
	if setting.IsEncrypted && setting.Value != "" {
		if decrypted, err := h.decrypt(setting.Value); err == nil {
			setting.Value = decrypted
		}
	}

	c.JSON(http.StatusOK, setting)
}

// UpdateSetting 更新设置
func (h *SettingHandler) UpdateSetting(c *gin.Context) {
	var input struct {
		Category    string `json:"category" binding:"required"`
		Key         string `json:"key" binding:"required"`
		Value       string `json:"value"`
		Description string `json:"description"`
		IsEncrypted bool   `json:"is_encrypted"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var setting models.Setting
	result := database.DB.Where("key = ?", input.Key).First(&setting)

	value := input.Value
	// 如果需要加密
	if input.IsEncrypted && value != "" {
		encrypted, err := h.encrypt(value)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt value"})
			return
		}
		value = encrypted
	}

	if result.Error != nil {
		// 创建新设置
		setting = models.Setting{
			Category:    input.Category,
			Key:         input.Key,
			Value:       value,
			Description: input.Description,
			IsEncrypted: input.IsEncrypted,
		}
		if err := database.DB.Create(&setting).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create setting"})
			return
		}
	} else {
		// 更新现有设置
		setting.Value = value
		setting.Description = input.Description
		setting.IsEncrypted = input.IsEncrypted
		if err := database.DB.Save(&setting).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update setting"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Setting updated successfully", "setting": setting})
}

// BatchUpdateSettings 批量更新设置
func (h *SettingHandler) BatchUpdateSettings(c *gin.Context) {
	var input struct {
		Settings []struct {
			Category    string `json:"category" binding:"required"`
			Key         string `json:"key" binding:"required"`
			Value       string `json:"value"`
			Description string `json:"description"`
			IsEncrypted bool   `json:"is_encrypted"`
		} `json:"settings" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, s := range input.Settings {
		value := s.Value

		// 如果是加密字段且值为空，跳过更新（保持原有值）
		if s.IsEncrypted && value == "" {
			continue
		}

		if s.IsEncrypted && value != "" {
			encrypted, err := h.encrypt(value)
			if err != nil {
				continue
			}
			value = encrypted
		}

		var setting models.Setting
		result := database.DB.Where("key = ?", s.Key).First(&setting)

		if result.Error != nil {
			// 新建记录时，如果是加密字段且值为空，跳过
			if s.IsEncrypted && value == "" {
				continue
			}
			setting = models.Setting{
				Category:    s.Category,
				Key:         s.Key,
				Value:       value,
				Description: s.Description,
				IsEncrypted: s.IsEncrypted,
			}
			database.DB.Create(&setting)
		} else {
			setting.Value = value
			setting.Description = s.Description
			database.DB.Save(&setting)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Settings updated successfully"})
}

// DeleteSetting 删除设置
func (h *SettingHandler) DeleteSetting(c *gin.Context) {
	key := c.Param("key")

	if err := database.DB.Where("key = ?", key).Delete(&models.Setting{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete setting"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Setting deleted successfully"})
}

// ListDictionaries 列出所有字典
func (h *SettingHandler) ListDictionaries(c *gin.Context) {
	dictType := c.Query("type")

	var dictionaries []models.Dictionary
	query := database.DB
	if dictType != "" {
		query = query.Where("type = ?", dictType)
	}

	if err := query.Order("is_default DESC, created_at DESC").Find(&dictionaries).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get dictionaries"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"dictionaries": dictionaries})
}

// 字典管理功能已迁移到 dictionary_handler.go

// encrypt 加密字符串
func (h *SettingHandler) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(h.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt 解密字符串
func (h *SettingHandler) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(h.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// countLines 统计文件行数
func (h *SettingHandler) countLines(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
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

	return lineCount, scanner.Err()
}
