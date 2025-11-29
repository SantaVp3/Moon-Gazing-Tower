package api

import (
	"strconv"

	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
)

type DashboardHandler struct {
	assetService *service.AssetService
	taskService  *service.TaskService
	vulnService  *service.VulnService
	nodeService  *service.NodeService
}

func NewDashboardHandler() *DashboardHandler {
	return &DashboardHandler{
		assetService: service.NewAssetService(),
		taskService:  service.NewTaskService(),
		vulnService:  service.NewVulnService(),
		nodeService:  service.NewNodeService(),
	}
}

// GetDashboardStats returns dashboard statistics
// GET /api/dashboard/stats
func (h *DashboardHandler) GetDashboardStats(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	
	// Get asset stats
	assetStats, _ := h.assetService.GetAssetStats(workspaceID)
	
	// Get task stats
	taskStats, _ := h.taskService.GetTaskStats(workspaceID)
	
	// Get vulnerability stats
	vulnStats, _ := h.vulnService.GetVulnStats(workspaceID)
	
	// Get node stats
	nodeStats, _ := h.nodeService.GetNodeStats()
	
	utils.Success(c, gin.H{
		"assets":          assetStats,
		"tasks":           taskStats,
		"vulnerabilities": vulnStats,
		"nodes":           nodeStats,
	})
}

// GetRecentTasks returns recent tasks
// GET /api/dashboard/recent-tasks
func (h *DashboardHandler) GetRecentTasks(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	
	tasks, _, err := h.taskService.ListTasks(workspaceID, "", "", 1, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.Success(c, tasks)
}

// GetRecentVulnerabilities returns recent vulnerabilities
// GET /api/dashboard/recent-vulns
func (h *DashboardHandler) GetRecentVulnerabilities(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	
	vulns, _, err := h.vulnService.ListVulnerabilities(workspaceID, "", "", "", 1, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.Success(c, vulns)
}

// GetRecentAssets returns recent assets
// GET /api/dashboard/recent-assets
func (h *DashboardHandler) GetRecentAssets(c *gin.Context) {
	workspaceID := c.Query("workspace_id")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	
	assets, _, err := h.assetService.ListAssets(workspaceID, "", "", nil, 1, limit)
	if err != nil {
		utils.Error(c, utils.ErrCodeDatabaseError, err.Error())
		return
	}
	
	utils.Success(c, assets)
}

// GetTrends returns trend data for the dashboard
// GET /api/dashboard/trends?days=7
func (h *DashboardHandler) GetTrends(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days <= 0 {
		days = 7
	}
	if days > 30 {
		days = 30
	}

	// Generate sample trend data for the last N days
	trends := make([]map[string]interface{}, 0, days)
	for i := days - 1; i >= 0; i-- {
		trends = append(trends, map[string]interface{}{
			"date":            i,
			"assets":          0,
			"vulnerabilities": 0,
			"tasks":           0,
		})
	}

	utils.Success(c, trends)
}

// GetRecentActivities returns recent activities
// GET /api/dashboard/activities?limit=5
func (h *DashboardHandler) GetRecentActivities(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}

	// Return empty activities for now
	activities := make([]map[string]interface{}, 0)

	utils.Success(c, activities)
}
