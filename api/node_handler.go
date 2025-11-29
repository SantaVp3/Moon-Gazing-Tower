package api

import (
	"strconv"

	"moongazing/models"
	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

type NodeHandler struct {
	nodeService *service.NodeService
}

func NewNodeHandler() *NodeHandler {
	return &NodeHandler{
		nodeService: service.NewNodeService(),
	}
}

// ListNodes lists all scanner nodes
// GET /api/nodes
func (h *NodeHandler) ListNodes(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	nodeType := c.Query("type")
	status := c.Query("status")
	
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	
	nodes, total, err := h.nodeService.ListNodes(nodeType, status, page, pageSize)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.SuccessWithPagination(c, nodes, total, page, pageSize)
}

// GetNode gets a single node by ID
// GET /api/nodes/:id
func (h *NodeHandler) GetNode(c *gin.Context) {
	nodeID := c.Param("id")
	
	node, err := h.nodeService.GetNodeByID(nodeID)
	if err != nil {
		utils.NotFound(c, err.Error())
		return
	}
	
	utils.Success(c, node)
}

// RegisterNode registers a new scanner node
// POST /api/nodes/register
func (h *NodeHandler) RegisterNode(c *gin.Context) {
	var req struct {
		NodeID       string               `json:"node_id"`
		Name         string               `json:"name" binding:"required"`
		Description  string               `json:"description"`
		Type         models.NodeType      `json:"type" binding:"required"`
		IP           string               `json:"ip" binding:"required"`
		Port         int                  `json:"port" binding:"required"`
		Version      string               `json:"version"`
		Capabilities []string             `json:"capabilities"`
		MaxTasks     int                  `json:"max_tasks"`
		SystemInfo   models.NodeSystemInfo `json:"system_info"`
		Tags         []string             `json:"tags"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误: "+err.Error())
		return
	}
	
	node := &models.ScannerNode{
		NodeID:            req.NodeID,
		Name:              req.Name,
		Description:       req.Description,
		Type:              req.Type,
		IP:                req.IP,
		Port:              req.Port,
		Version:           req.Version,
		Capabilities:      req.Capabilities,
		MaxTasks:          req.MaxTasks,
		SystemInfo:        req.SystemInfo,
		Tags:              req.Tags,
		HeartbeatInterval: 30,
	}
	
	if node.MaxTasks == 0 {
		node.MaxTasks = 10
	}
	
	if err := h.nodeService.RegisterNode(node); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "注册成功", gin.H{
		"id":      node.ID.Hex(),
		"node_id": node.NodeID,
	})
}

// UpdateNode updates a node
// PUT /api/nodes/:id
func (h *NodeHandler) UpdateNode(c *gin.Context) {
	nodeID := c.Param("id")
	
	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	// Remove protected fields
	delete(req, "id")
	delete(req, "_id")
	delete(req, "node_id")
	delete(req, "created_at")
	
	if err := h.nodeService.UpdateNode(nodeID, req); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "更新成功", nil)
}

// DeleteNode deletes a node
// DELETE /api/nodes/:id
func (h *NodeHandler) DeleteNode(c *gin.Context) {
	nodeID := c.Param("id")
	
	if err := h.nodeService.DeleteNode(nodeID); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "删除成功", nil)
}

// Heartbeat handles node heartbeat
// POST /api/nodes/:id/heartbeat
func (h *NodeHandler) Heartbeat(c *gin.Context) {
	nodeID := c.Param("id")
	
	var req struct {
		SystemInfo   models.NodeSystemInfo `json:"system_info"`
		CurrentTasks int                   `json:"current_tasks"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.nodeService.Heartbeat(nodeID, req.SystemInfo, req.CurrentTasks); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "心跳更新成功", nil)
}

// SetNodeStatus sets node status
// PUT /api/nodes/:id/status
func (h *NodeHandler) SetNodeStatus(c *gin.Context) {
	nodeID := c.Param("id")
	
	var req struct {
		Status models.NodeStatus `json:"status" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "参数错误")
		return
	}
	
	if err := h.nodeService.SetNodeStatus(nodeID, req.Status); err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.SuccessWithMessage(c, "状态更新成功", nil)
}

// GetNodeStats returns node statistics
// GET /api/nodes/stats
func (h *NodeHandler) GetNodeStats(c *gin.Context) {
	stats, err := h.nodeService.GetNodeStats()
	if err != nil {
		utils.Error(c, utils.ErrCodeInternalError, err.Error())
		return
	}
	
	utils.Success(c, stats)
}
