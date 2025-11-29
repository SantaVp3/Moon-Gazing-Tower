package api

import (
	"strconv"
	"strings"

	"moongazing/models"
	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AssetHandler struct {
	assetService *service.AssetService
}

func NewAssetHandler() *AssetHandler {
	return &AssetHandler{
		assetService: service.NewAssetService(),
	}
}

// ListAssets lists assets with filtering and pagination
// GET /api/assets
func (h *AssetHandler) ListAssets(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	workspaceID := c.Query("workspace_id")
	assetType := c.Query("type")
	keyword := c.Query("keyword")
	tagsStr := c.Query("tags")
	
	var tags []string
	if tagsStr != "" {
		tags = strings.Split(tagsStr, ",")
	}
	
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	
	assets, total, err := h.assetService.ListAssets(workspaceID, assetType, keyword, tags, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.SuccessWithPagination(c, assets, total, page, pageSize)
}

// GetAsset gets a single asset by ID
// GET /api/assets/:id
func (h *AssetHandler) GetAsset(c *gin.Context) {
	assetID := c.Param("id")
	
	asset, err := h.assetService.GetAssetByID(assetID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.Success(c, asset)
}

// CreateAsset creates a new asset
// POST /api/assets
func (h *AssetHandler) CreateAsset(c *gin.Context) {
	var req struct {
		WorkspaceID string            `json:"workspace_id"`
		Type        models.AssetType  `json:"type" binding:"required"`
		Value       string            `json:"value" binding:"required"`
		Title       string            `json:"title"`
		Tags        []string          `json:"tags"`
		GroupID     string            `json:"group_id"`
		IPInfo      *models.IPInfo    `json:"ip_info"`
		DomainInfo  *models.DomainInfo `json:"domain_info"`
		WebInfo     *models.WebInfo   `json:"web_info"`
		APPInfo     *models.APPInfo   `json:"app_info"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	asset := &models.Asset{
		Type:       req.Type,
		Value:      req.Value,
		Title:      req.Title,
		Status:     1,
		Tags:       req.Tags,
		Source:     "manual",
		IPInfo:     req.IPInfo,
		DomainInfo: req.DomainInfo,
		WebInfo:    req.WebInfo,
		APPInfo:    req.APPInfo,
	}
	
	if req.WorkspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(req.WorkspaceID)
		asset.WorkspaceID = wsID
	}
	
	if req.GroupID != "" {
		groupID, _ := primitive.ObjectIDFromHex(req.GroupID)
		asset.GroupID = groupID
	}
	
	if err := h.assetService.CreateAsset(asset); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": asset.ID.Hex()})
}

// UpdateAsset updates an asset
// PUT /api/assets/:id
func (h *AssetHandler) UpdateAsset(c *gin.Context) {
	assetID := c.Param("id")
	
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "created_at")
	
	if err := h.assetService.UpdateAsset(assetID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeleteAsset deletes an asset
// DELETE /api/assets/:id
func (h *AssetHandler) DeleteAsset(c *gin.Context) {
	assetID := c.Param("id")
	
	if err := h.assetService.DeleteAsset(assetID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// BatchDeleteAssets deletes multiple assets
// POST /api/assets/batch-delete
func (h *AssetHandler) BatchDeleteAssets(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	count, err := h.assetService.BatchDeleteAssets(req.IDs)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", gin.H{"deleted_count": count})
}

// AddAssetTags adds tags to an asset
// POST /api/assets/:id/tags
func (h *AssetHandler) AddAssetTags(c *gin.Context) {
	assetID := c.Param("id")
	
	var req struct {
		Tags []string `json:"tags" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.assetService.AddAssetTags(assetID, req.Tags); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "添加标签成功", nil)
}

// RemoveAssetTags removes tags from an asset
// DELETE /api/assets/:id/tags
func (h *AssetHandler) RemoveAssetTags(c *gin.Context) {
	assetID := c.Param("id")
	
	var req struct {
		Tags []string `json:"tags" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.assetService.RemoveAssetTags(assetID, req.Tags); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "移除标签成功", nil)
}

// GetAssetStats returns asset statistics
// GET /api/assets/stats
func (h *AssetHandler) GetAssetStats(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	
	stats, err := h.assetService.GetAssetStats(workspaceID)
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.Success(c, stats)
}

// ListAssetGroups lists asset groups
// GET /api/assets/groups
func (h *AssetHandler) ListAssetGroups(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	
	groups, err := h.assetService.ListAssetGroups(workspaceID)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.Success(c, groups)
}

// CreateAssetGroup creates a new asset group
// POST /api/assets/groups
func (h *AssetHandler) CreateAssetGroup(c *gin.Context) {
	var req struct {
		WorkspaceID string `json:"workspace_id"`
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		ParentID    string `json:"parent_id"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	group := &models.AssetGroup{
		Name:        req.Name,
		Description: req.Description,
	}
	
	if req.WorkspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(req.WorkspaceID)
		group.WorkspaceID = wsID
	}
	
	if req.ParentID != "" {
		parentID, _ := primitive.ObjectIDFromHex(req.ParentID)
		group.ParentID = parentID
	}
	
	if err := h.assetService.CreateAssetGroup(group); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": group.ID.Hex()})
}

// DeleteAssetGroup deletes an asset group
// DELETE /api/assets/groups/:id
func (h *AssetHandler) DeleteAssetGroup(c *gin.Context) {
	groupID := c.Param("id")
	
	if err := h.assetService.DeleteAssetGroup(groupID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// ListBlackWhiteList lists blacklist or whitelist entries
// GET /api/assets/blackwhitelist
func (h *AssetHandler) ListBlackWhiteList(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	workspaceID := c.Query("workspace_id")
	listType := c.Query("type")
	
	items, total, err := h.assetService.ListBlackWhiteList(workspaceID, listType, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.SuccessWithPagination(c, items, total, page, pageSize)
}

// CreateBlackWhiteList creates a blacklist or whitelist entry
// POST /api/assets/blackwhitelist
func (h *AssetHandler) CreateBlackWhiteList(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req struct {
		WorkspaceID string `json:"workspace_id"`
		Type        string `json:"type" binding:"required,oneof=black white"`
		Category    string `json:"category" binding:"required,oneof=ip domain url"`
		Value       string `json:"value" binding:"required"`
		Reason      string `json:"reason"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	item := &models.BlackWhiteList{
		Type:     req.Type,
		Category: req.Category,
		Value:    req.Value,
		Reason:   req.Reason,
	}
	
	if req.WorkspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(req.WorkspaceID)
		item.WorkspaceID = wsID
	}
	
	if userID != nil {
		uid, _ := primitive.ObjectIDFromHex(userID.(string))
		item.CreatedBy = uid
	}
	
	if err := h.assetService.CreateBlackWhiteList(item); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "创建成功", gin.H{"id": item.ID.Hex()})
}

// DeleteBlackWhiteList deletes a blacklist or whitelist entry
// DELETE /api/assets/blackwhitelist/:id
func (h *AssetHandler) DeleteBlackWhiteList(c *gin.Context) {
	itemID := c.Param("id")
	
	if err := h.assetService.DeleteBlackWhiteList(itemID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}
