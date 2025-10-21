package handlers

import (
	"fmt"
	"net/http"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/gin-gonic/gin"
)

// PolicyHandler 策略处理器
type PolicyHandler struct{}

// NewPolicyHandler 创建策略处理器
func NewPolicyHandler() *PolicyHandler {
	return &PolicyHandler{}
}

// ListPolicies 列出所有策略
func (h *PolicyHandler) ListPolicies(c *gin.Context) {
	name := c.Query("name")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	var pageInt, pageSizeInt int
	if _, err := fmt.Sscanf(page, "%d", &pageInt); err != nil || pageInt < 1 {
		pageInt = 1
	}
	if _, err := fmt.Sscanf(pageSize, "%d", &pageSizeInt); err != nil || pageSizeInt < 1 {
		pageSizeInt = 20
	}

	query := database.DB.Model(&models.Policy{})

	if name != "" {
		query = query.Where("name LIKE ?", "%"+name+"%")
	}

	var total int64
	query.Count(&total)

	var policies []models.Policy
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&policies).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch policies"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"policies":    policies,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// GetPolicy 获取单个策略
func (h *PolicyHandler) GetPolicy(c *gin.Context) {
	id := c.Param("id")

	var policy models.Policy
	if err := database.DB.First(&policy, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// CreatePolicy 创建策略
func (h *PolicyHandler) CreatePolicy(c *gin.Context) {
	var policy models.Policy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 设置创建者
	userID, exists := c.Get("userID")
	if exists {
		policy.CreatedBy = userID.(string)
	}

	if err := database.DB.Create(&policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Policy created successfully",
		"policy":  policy,
	})
}

// UpdatePolicy 更新策略
func (h *PolicyHandler) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")

	var policy models.Policy
	if err := database.DB.First(&policy, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var updateData models.Policy
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	policy.Name = updateData.Name
	policy.Description = updateData.Description
	policy.Config = updateData.Config
	policy.IsDefault = updateData.IsDefault

	if err := database.DB.Save(&policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Policy updated successfully",
		"policy":  policy,
	})
}

// DeletePolicy 删除策略
func (h *PolicyHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")

	var policy models.Policy
	if err := database.DB.First(&policy, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// 检查是否为默认策略
	if policy.IsDefault {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default policy"})
		return
	}

	if err := database.DB.Delete(&policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted successfully"})
}

// SetDefaultPolicy 设置默认策略
func (h *PolicyHandler) SetDefaultPolicy(c *gin.Context) {
	id := c.Param("id")

	var policy models.Policy
	if err := database.DB.First(&policy, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// 取消其他策略的默认状态
	database.DB.Model(&models.Policy{}).Where("is_default = ?", true).Update("is_default", false)

	// 设置当前策略为默认
	policy.IsDefault = true
	if err := database.DB.Save(&policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set default policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Default policy set successfully",
		"policy":  policy,
	})
}

// GetDefaultPolicy 获取默认策略
func (h *PolicyHandler) GetDefaultPolicy(c *gin.Context) {
	var policy models.Policy
	if err := database.DB.Where("is_default = ?", true).First(&policy).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No default policy found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// BatchDelete 批量删除策略
func (h *PolicyHandler) BatchDelete(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查是否包含默认策略
	var count int64
	database.DB.Model(&models.Policy{}).Where("id IN ? AND is_default = ?", req.IDs, true).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default policy"})
		return
	}

	if err := database.DB.Where("id IN ?", req.IDs).Delete(&models.Policy{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Policies deleted successfully",
		"count":   len(req.IDs),
	})
}

// GetStats 获取策略统计
func (h *PolicyHandler) GetStats(c *gin.Context) {
	var total int64
	database.DB.Model(&models.Policy{}).Count(&total)

	var defaultCount int64
	database.DB.Model(&models.Policy{}).Where("is_default = ?", true).Count(&defaultCount)

	c.JSON(http.StatusOK, gin.H{
		"total":         total,
		"default_count": defaultCount,
	})
}

