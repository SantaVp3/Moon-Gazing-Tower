package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/middleware"
	"github.com/reconmaster/backend/internal/models"
)

// AssetTagHandler 资产标签处理器
type AssetTagHandler struct{}

// NewAssetTagHandler 创建资产标签处理器
func NewAssetTagHandler() *AssetTagHandler {
	return &AssetTagHandler{}
}

// ListTags 获取标签列表
func (h *AssetTagHandler) ListTags(c *gin.Context) {
	category := c.Query("category")
	
	query := database.DB.Model(&models.AssetTag{})
	
	if category != "" {
		query = query.Where("category = ?", category)
	}
	
	var tags []models.AssetTag
	if err := query.Order("created_at DESC").Find(&tags).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tags"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// CreateTag 创建标签
func (h *AssetTagHandler) CreateTag(c *gin.Context) {
	var req models.CreateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	userID := middleware.GetCurrentUserID(c)
	
	tag := models.AssetTag{
		Name:        req.Name,
		Color:       req.Color,
		Description: req.Description,
		Category:    req.Category,
		CreatedBy:   userID,
	}
	
	if tag.Color == "" {
		tag.Color = "#3B82F6" // 默认蓝色
	}
	
	if err := database.DB.Create(&tag).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tag"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{"tag": tag})
}

// UpdateTag 更新标签
func (h *AssetTagHandler) UpdateTag(c *gin.Context) {
	id := c.Param("id")
	
	var req models.UpdateTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	var tag models.AssetTag
	if err := database.DB.First(&tag, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
		return
	}
	
	// 更新字段
	if req.Name != "" {
		tag.Name = req.Name
	}
	if req.Color != "" {
		tag.Color = req.Color
	}
	if req.Description != "" {
		tag.Description = req.Description
	}
	if req.Category != "" {
		tag.Category = req.Category
	}
	
	if err := database.DB.Save(&tag).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tag"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"tag": tag})
}

// DeleteTag 删除标签
func (h *AssetTagHandler) DeleteTag(c *gin.Context) {
	id := c.Param("id")
	
	// 删除标签关联
	database.DB.Where("tag_id = ?", id).Delete(&models.AssetTagRelation{})
	
	// 删除标签
	if err := database.DB.Delete(&models.AssetTag{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tag"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Tag deleted successfully"})
}

// AddAssetTags 为资产添加标签
func (h *AssetTagHandler) AddAssetTags(c *gin.Context) {
	var req models.AddAssetTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	userID := middleware.GetCurrentUserID(c)
	
	// 先删除该资产的所有标签
	database.DB.Where("asset_type = ? AND asset_id = ?", req.AssetType, req.AssetID).
		Delete(&models.AssetTagRelation{})
	
	// 添加新标签
	for _, tagID := range req.TagIDs {
		relation := models.AssetTagRelation{
			TagID:     tagID,
			AssetType: req.AssetType,
			AssetID:   req.AssetID,
			CreatedBy: userID,
		}
		database.DB.Create(&relation)
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "Tags added successfully"})
}

// GetAssetTags 获取资产的标签
func (h *AssetTagHandler) GetAssetTags(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")
	
	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}
	
	var relations []models.AssetTagRelation
	database.DB.Where("asset_type = ? AND asset_id = ?", assetType, assetID).Find(&relations)
	
	tagIDs := make([]string, len(relations))
	for i, rel := range relations {
		tagIDs[i] = rel.TagID
	}
	
	var tags []models.AssetTag
	if len(tagIDs) > 0 {
		database.DB.Where("id IN ?", tagIDs).Find(&tags)
	}
	
	c.JSON(http.StatusOK, gin.H{"tags": tags})
}

// SearchAssetsByTag 根据标签搜索资产
func (h *AssetTagHandler) SearchAssetsByTag(c *gin.Context) {
	tagID := c.Query("tag_id")
	assetType := c.Query("asset_type") // 可选，过滤资产类型
	
	if tagID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tag_id is required"})
		return
	}
	
	query := database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ?", tagID)
	
	if assetType != "" {
		query = query.Where("asset_type = ?", assetType)
	}
	
	var relations []models.AssetTagRelation
	query.Find(&relations)
	
	// 按资产类型分组
	result := map[string][]string{
		"domains": []string{},
		"ips":     []string{},
		"sites":   []string{},
		"ports":   []string{},
	}
	
	for _, rel := range relations {
		switch rel.AssetType {
		case "domain":
			result["domains"] = append(result["domains"], rel.AssetID)
		case "ip":
			result["ips"] = append(result["ips"], rel.AssetID)
		case "site":
			result["sites"] = append(result["sites"], rel.AssetID)
		case "port":
			result["ports"] = append(result["ports"], rel.AssetID)
		}
	}
	
	c.JSON(http.StatusOK, gin.H{"assets": result})
}

// GetTagStats 获取标签统计
func (h *AssetTagHandler) GetTagStats(c *gin.Context) {
	tagID := c.Param("id")
	
	var tag models.AssetTag
	if err := database.DB.First(&tag, "id = ?", tagID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tag not found"})
		return
	}
	
	// 统计该标签关联的资产数量
	var stats struct {
		TotalAssets  int64 `json:"total_assets"`
		DomainCount  int64 `json:"domain_count"`
		IPCount      int64 `json:"ip_count"`
		SiteCount    int64 `json:"site_count"`
		PortCount    int64 `json:"port_count"`
	}
	
	database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ?", tagID).Count(&stats.TotalAssets)
	database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ? AND asset_type = ?", tagID, "domain").Count(&stats.DomainCount)
	database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ? AND asset_type = ?", tagID, "ip").Count(&stats.IPCount)
	database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ? AND asset_type = ?", tagID, "site").Count(&stats.SiteCount)
	database.DB.Model(&models.AssetTagRelation{}).Where("tag_id = ? AND asset_type = ?", tagID, "port").Count(&stats.PortCount)
	
	c.JSON(http.StatusOK, gin.H{
		"tag":   tag,
		"stats": stats,
	})
}
