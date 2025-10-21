package handlers

import (
	"net/http"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/export"
	"github.com/reconmaster/backend/internal/models"
	"github.com/gin-gonic/gin"
)

// ExportHandler 导出处理器
type ExportHandler struct {
	exporter *export.Exporter
}

// NewExportHandler 创建导出处理器
func NewExportHandler() *ExportHandler {
	return &ExportHandler{
		exporter: export.NewExporter("./exports"),
	}
}

// ExportTask 导出任务数据
func (h *ExportHandler) ExportTask(c *gin.Context) {
	taskID := c.Param("id")
	format := c.DefaultQuery("format", "json") // json, csv, html

	// 获取任务
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	// 获取所有相关数据
	var domains []models.Domain
	var ips []models.IP
	var ports []models.Port
	var sites []models.Site
	var urls []models.URL
	var vulns []models.Vulnerability

	database.DB.Where("task_id = ?", taskID).Find(&domains)
	database.DB.Where("task_id = ?", taskID).Find(&ips)
	database.DB.Where("task_id = ?", taskID).Find(&ports)
	database.DB.Where("task_id = ?", taskID).Find(&sites)
	database.DB.Where("task_id = ?", taskID).Find(&urls)
	database.DB.Where("task_id = ?", taskID).Find(&vulns)

	exportData := &export.ExportData{
		Task:            &task,
		Domains:         domains,
		IPs:             ips,
		Ports:           ports,
		Sites:           sites,
		URLs:            urls,
		Vulnerabilities: vulns,
		ExportTime:      time.Now(),
	}

	var filename string
	var err error

	switch format {
	case "json":
		filename, err = h.exporter.ExportToJSON(exportData)
	case "csv":
		// CSV 导出域名数据（默认）
		if len(exportData.Domains) > 0 {
			filename, err = h.exporter.ExportDomainsToCSV(exportData.Domains, taskID)
		} else if len(exportData.Sites) > 0 {
			filename, err = h.exporter.ExportSitesToCSV(exportData.Sites, taskID)
		} else if len(exportData.Ports) > 0 {
			filename, err = h.exporter.ExportPortsToCSV(exportData.Ports, taskID)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No data to export"})
			return
		}
	case "html":
		filename, err = h.exporter.GenerateReport(exportData)
	case "all":
		files, exportErr := h.exporter.ExportAll(exportData)
		if exportErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "Export completed",
			"files":   files,
		})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Export failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Export completed",
		"filename": filename,
	})
}

// DownloadExport 下载导出文件
func (h *ExportHandler) DownloadExport(c *gin.Context) {
	filename := c.Query("file")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filename required"})
		return
	}

	// 安全检查：防止路径遍历
	if containsPathTraversal(filename) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}

	filepath := "./exports/" + filename
	c.File(filepath)
}

// containsPathTraversal 检查路径遍历
func containsPathTraversal(path string) bool {
	return len(path) > 0 && (path[0] == '/' || path[0] == '\\' || 
		len(path) > 1 && (path[:2] == ".." || path[:2] == "~/"))
}
