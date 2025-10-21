package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

// AssetHandler 资产处理器
type AssetHandler struct{}

// NewAssetHandler 创建资产处理器
func NewAssetHandler() *AssetHandler {
	return &AssetHandler{}
}

// ListDomains 列出域名资产
func (h *AssetHandler) ListDomains(c *gin.Context) {
	taskID := c.Query("task_id")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")
	search := c.Query("search")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}

	query := database.DB.Model(&models.Domain{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	if search != "" {
		query = query.Where("domain LIKE ?", "%"+search+"%")
	}

	var total int64
	query.Count(&total)

	var domains []models.Domain
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"domains":     domains,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListIPs 列出IP资产
func (h *AssetHandler) ListIPs(c *gin.Context) {
	taskID := c.Query("task_id")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}

	query := database.DB.Model(&models.IP{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	var total int64
	query.Count(&total)

	var ips []models.IP
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&ips).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch IPs"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"ips":         ips,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListPorts 列出端口资产
func (h *AssetHandler) ListPorts(c *gin.Context) {
	taskID := c.Query("task_id")
	ipAddress := c.Query("ip")
	portStr := c.Query("port")
	service := c.Query("service")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}
	// 限制单页最大数量，防止查询过多数据导致性能问题
	const maxPageSize = 200
	if pageSizeInt > maxPageSize {
		pageSizeInt = maxPageSize
	}

	query := database.DB.Model(&models.Port{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	if ipAddress != "" {
		query = query.Where("ip_address = ?", ipAddress)
	}

	// 支持端口号筛选
	if portStr != "" {
		var portInt int
		if _, err := fmt.Sscanf(portStr, "%d", &portInt); err == nil && portInt > 0 && portInt <= 65535 {
			query = query.Where("port = ?", portInt)
		}
	}

	// 支持服务筛选
	if service != "" {
		query = query.Where("service LIKE ?", "%"+service+"%")
	}

	var total int64
	query.Count(&total)

	var ports []models.Port
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("port ASC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&ports).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch ports"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"ports":       ports,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListSites 列出站点资产
func (h *AssetHandler) ListSites(c *gin.Context) {
	taskID := c.Query("task_id")
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "50")

	var pageInt, pageSizeInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(pageSize, "%d", &pageSizeInt)
	if pageInt < 1 {
		pageInt = 1
	}
	if pageSizeInt < 1 {
		pageSizeInt = 50
	}

	query := database.DB.Model(&models.Site{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	var total int64
	query.Count(&total)

	var sites []models.Site
	offset := (pageInt - 1) * pageSizeInt
	if err := query.Order("created_at DESC").
		Limit(pageSizeInt).
		Offset(offset).
		Find(&sites).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sites"})
		return
	}

	totalPages := int((total + int64(pageSizeInt) - 1) / int64(pageSizeInt))

	c.JSON(http.StatusOK, gin.H{
		"sites":       sites,
		"total":       total,
		"page":        pageInt,
		"page_size":   pageSizeInt,
		"total_pages": totalPages,
	})
}

// ListVulnerabilities 列出漏洞信息
func (h *AssetHandler) ListVulnerabilities(c *gin.Context) {
	taskID := c.Query("task_id")
	severity := c.Query("severity")

	query := database.DB.Model(&models.Vulnerability{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}

	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	var vulns []models.Vulnerability
	if err := query.Order("created_at DESC").Find(&vulns).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch vulnerabilities"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"vulnerabilities": vulns})
}

// GetAssetStats 获取资产统计信息
func (h *AssetHandler) GetAssetStats(c *gin.Context) {
	taskID := c.Query("task_id")

	var stats struct {
		Domains         int64 `json:"domains"`
		IPs             int64 `json:"ips"`
		Ports           int64 `json:"ports"`
		Sites           int64 `json:"sites"`
		URLs            int64 `json:"urls"`
		Vulnerabilities int64 `json:"vulnerabilities"`
	}

	// 统计各类资产数量
	if taskID != "" {
		database.DB.Model(&models.Domain{}).Where("task_id = ?", taskID).Count(&stats.Domains)
		database.DB.Model(&models.IP{}).Where("task_id = ?", taskID).Count(&stats.IPs)
		database.DB.Model(&models.Port{}).Where("task_id = ?", taskID).Count(&stats.Ports)
		database.DB.Model(&models.Site{}).Where("task_id = ?", taskID).Count(&stats.Sites)
		database.DB.Model(&models.URL{}).Where("task_id = ?", taskID).Count(&stats.URLs)
		database.DB.Model(&models.Vulnerability{}).Where("task_id = ?", taskID).Count(&stats.Vulnerabilities)
	} else {
		database.DB.Model(&models.Domain{}).Count(&stats.Domains)
		database.DB.Model(&models.IP{}).Count(&stats.IPs)
		database.DB.Model(&models.Port{}).Count(&stats.Ports)
		database.DB.Model(&models.Site{}).Count(&stats.Sites)
		database.DB.Model(&models.URL{}).Count(&stats.URLs)
		database.DB.Model(&models.Vulnerability{}).Count(&stats.Vulnerabilities)
	}

	c.JSON(http.StatusOK, stats)
}

// ListURLs 获取URL列表
func (h *AssetHandler) ListURLs(c *gin.Context) {
	taskID := c.Query("task_id")
	url := c.Query("url")
	source := c.Query("source")
	statusCode := c.Query("status_code")

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	var urls []models.CrawlerResult
	query := database.DB.Model(&models.CrawlerResult{})

	// 筛选条件
	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if url != "" {
		query = query.Where("url LIKE ?", "%"+url+"%")
	}
	if source != "" {
		query = query.Where("source = ?", source)
	}
	if statusCode != "" {
		if code, err := strconv.Atoi(statusCode); err == nil {
			query = query.Where("status_code = ?", code)
		}
	}

	// 计算总数
	var total int64
	query.Count(&total)

	// 分页查询
	offset := (page - 1) * pageSize
	query.Order("created_at DESC").Limit(pageSize).Offset(offset).Find(&urls)

	// 计算总页数
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"urls":        urls,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": totalPages,
	})
}
