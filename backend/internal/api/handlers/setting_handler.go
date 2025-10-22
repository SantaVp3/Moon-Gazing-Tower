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
	"path/filepath"
	"strings"
	"time"

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

// UploadDictionary 上传字典
func (h *SettingHandler) UploadDictionary(c *gin.Context) {
	userID := c.GetString("userID")

	name := c.PostForm("name")
	dictType := c.PostForm("type")
	description := c.PostForm("description")

	if name == "" || dictType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name and type are required"})
		return
	}

	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is required"})
		return
	}

	// 创建字典目录
	dictDir := filepath.Join("./configs/dicts", dictType)
	os.MkdirAll(dictDir, 0755)

	// 保存文件
	filename := fmt.Sprintf("%d_%s", time.Now().Unix(), file.Filename)
	filePath := filepath.Join(dictDir, filename)

	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// 统计行数
	lineCount, err := h.countLines(filePath)
	if err != nil {
		lineCount = 0
	}

	// 创建字典记录
	dict := models.Dictionary{
		Name:        name,
		Type:        dictType,
		FilePath:    filePath,
		Size:        file.Size,
		LineCount:   lineCount,
		Description: description,
		CreatedBy:   userID,
	}

	if err := database.DB.Create(&dict).Error; err != nil {
		os.Remove(filePath) // 删除文件
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dictionary record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dictionary uploaded successfully", "dictionary": dict})
}

// DeleteDictionary 删除字典
func (h *SettingHandler) DeleteDictionary(c *gin.Context) {
	id := c.Param("id")

	var dict models.Dictionary
	if err := database.DB.Where("id = ?", id).First(&dict).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	if dict.IsDefault {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default dictionary"})
		return
	}

	// 删除文件
	if dict.FilePath != "" {
		os.Remove(dict.FilePath)
	}

	// 删除记录
	if err := database.DB.Delete(&dict).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete dictionary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dictionary deleted successfully"})
}

// SetDefaultDictionary 设置默认字典
func (h *SettingHandler) SetDefaultDictionary(c *gin.Context) {
	id := c.Param("id")

	var dict models.Dictionary
	if err := database.DB.Where("id = ?", id).First(&dict).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Dictionary not found"})
		return
	}

	// 取消同类型的其他默认字典
	database.DB.Model(&models.Dictionary{}).Where("type = ? AND is_default = ?", dict.Type, true).Update("is_default", false)

	// 设置为默认
	dict.IsDefault = true
	database.DB.Save(&dict)

	c.JSON(http.StatusOK, gin.H{"message": "Default dictionary set successfully"})
}

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
