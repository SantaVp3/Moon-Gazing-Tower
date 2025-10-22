package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/services"
)

// AssetProfileHandler 资产画像处理器
type AssetProfileHandler struct {
	service *services.AssetProfileService
}

// NewAssetProfileHandler 创建资产画像处理器
func NewAssetProfileHandler() *AssetProfileHandler {
	return &AssetProfileHandler{
		service: services.NewAssetProfileService(),
	}
}

// GetAssetProfile 获取资产画像
// GET /api/v1/assets/profile?asset_type=domain&asset_id=xxx
func (h *AssetProfileHandler) GetAssetProfile(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}

	profile, err := h.service.GetAssetProfile(assetType, assetID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"profile": profile})
}

// GetAssetRelations 获取资产关系
// GET /api/v1/assets/relations?asset_type=domain&asset_id=xxx
func (h *AssetProfileHandler) GetAssetRelations(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}

	relations, err := h.service.GetAssetRelations(assetType, assetID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"relations": relations})
}

// GetAssetGraph 获取资产关系图谱
// GET /api/v1/assets/graph?asset_type=domain&asset_id=xxx&depth=2
func (h *AssetProfileHandler) GetAssetGraph(c *gin.Context) {
	assetType := c.Query("asset_type")
	assetID := c.Query("asset_id")
	depthStr := c.DefaultQuery("depth", "2")

	if assetType == "" || assetID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_type and asset_id are required"})
		return
	}

	depth, err := strconv.Atoi(depthStr)
	if err != nil || depth < 1 || depth > 5 {
		depth = 2 // 默认深度为2
	}

	graph, err := h.service.GetAssetGraph(assetType, assetID, depth)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"graph": graph})
}

// AnalyzeCSegment C段分析
// GET /api/v1/assets/c-segment?ip=192.168.1.100
func (h *AssetProfileHandler) AnalyzeCSegment(c *gin.Context) {
	ip := c.Query("ip")

	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip is required"})
		return
	}

	analysis, err := h.service.AnalyzeCSegment(ip)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"analysis": analysis})
}
