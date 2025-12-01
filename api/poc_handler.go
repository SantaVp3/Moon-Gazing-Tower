package api

import (
	"net/http"
	"strconv"

	"moongazing/models"
	"moongazing/service"
	"moongazing/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

type POCHandler struct {
	pocService *service.POCService
}

func NewPOCHandler() *POCHandler {
	return &POCHandler{
		pocService: service.NewPOCService(),
	}
}

// ImportPOCsFromZip 从 ZIP 包导入 POC
// @Summary Import POCs from ZIP file
// @Tags pocs
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "ZIP file containing POCs"
// @Success 200 {object} map[string]interface{}
// @Router /api/pocs/import [post]
func (h *POCHandler) ImportPOCsFromZip(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		utils.BadRequest(c, "No file uploaded")
		return
	}

	// 检查文件类型
	if file.Header.Get("Content-Type") != "application/zip" &&
		file.Header.Get("Content-Type") != "application/x-zip-compressed" &&
		file.Header.Get("Content-Type") != "application/octet-stream" {
		// 也检查文件扩展名
		if len(file.Filename) < 4 || file.Filename[len(file.Filename)-4:] != ".zip" {
			utils.BadRequest(c, "Only ZIP files are allowed")
			return
		}
	}

	// 打开上传的文件
	src, err := file.Open()
	if err != nil {
		utils.InternalError(c, "Failed to open uploaded file")
		return
	}
	defer src.Close()

	// 调用 service 处理 ZIP 导入
	result, err := h.pocService.ImportFromZip(src, file.Size)
	if err != nil {
		utils.InternalError(c, "Failed to import POCs: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "POCs imported successfully",
		"data": gin.H{
			"imported": result.Imported,
			"failed":   result.Failed,
			"skipped":  result.Skipped,
			"errors":   result.Errors,
		},
	})
}

// CreatePOC godoc
// @Summary Create a new POC
// @Tags pocs
// @Accept json
// @Produce json
// @Param poc body models.POC true "POC object"
// @Success 201 {object} models.POC
// @Router /api/pocs [post]
func (h *POCHandler) CreatePOC(c *gin.Context) {
	var poc models.POC
	if err := c.ShouldBindJSON(&poc); err != nil {
		utils.BadRequest(c, "Invalid request body")
		return
	}
	
	if poc.Name == "" {
		utils.BadRequest(c, "POC name is required")
		return
	}
	
	if err := h.pocService.Create(&poc); err != nil {
		utils.InternalError(c, "Failed to create POC")
		return
	}
	
	c.JSON(http.StatusCreated, poc)
}

// GetPOC godoc
// @Summary Get POC by ID
// @Tags pocs
// @Produce json
// @Param id path string true "POC ID"
// @Success 200 {object} models.POC
// @Router /api/pocs/{id} [get]
func (h *POCHandler) GetPOC(c *gin.Context) {
	id := c.Param("id")
	
	poc, err := h.pocService.GetByID(id)
	if err != nil {
		utils.NotFound(c, "POC not found")
		return
	}
	
	c.JSON(http.StatusOK, poc)
}

// UpdatePOC godoc
// @Summary Update POC
// @Tags pocs
// @Accept json
// @Produce json
// @Param id path string true "POC ID"
// @Param poc body object true "POC update object"
// @Success 200 {object} map[string]string
// @Router /api/pocs/{id} [put]
func (h *POCHandler) UpdatePOC(c *gin.Context) {
	id := c.Param("id")
	
	var update map[string]interface{}
	if err := c.ShouldBindJSON(&update); err != nil {
		utils.BadRequest(c, "Invalid request body")
		return
	}
	
	// Remove fields that shouldn't be updated directly
	delete(update, "_id")
	delete(update, "created_at")
	
	if err := h.pocService.Update(id, bson.M(update)); err != nil {
		utils.InternalError(c, "Failed to update POC")
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "POC updated successfully"})
}

// DeletePOC godoc
// @Summary Delete POC
// @Tags pocs
// @Produce json
// @Param id path string true "POC ID"
// @Success 200 {object} map[string]string
// @Router /api/pocs/{id} [delete]
func (h *POCHandler) DeletePOC(c *gin.Context) {
	id := c.Param("id")
	
	if err := h.pocService.Delete(id); err != nil {
		utils.InternalError(c, "Failed to delete POC")
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "POC deleted successfully"})
}

// ListPOCs godoc
// @Summary List POCs
// @Tags pocs
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param type query string false "POC type"
// @Param severity query string false "Severity"
// @Param enabled query bool false "Enabled status"
// @Param search query string false "Search keyword"
// @Success 200 {object} service.POCListResult
// @Router /api/pocs [get]
func (h *POCHandler) ListPOCs(c *gin.Context) {
	page, _ := strconv.ParseInt(c.DefaultQuery("page", "1"), 10, 64)
	pageSize, _ := strconv.ParseInt(c.DefaultQuery("page_size", "20"), 10, 64)
	
	params := service.POCListParams{
		Page:     page,
		PageSize: pageSize,
		Type:     c.Query("type"),
		Severity: c.Query("severity"),
		Search:   c.Query("search"),
	}
	
	if enabledStr := c.Query("enabled"); enabledStr != "" {
		enabled := enabledStr == "true"
		params.Enabled = &enabled
	}
	
	result, err := h.pocService.List(params)
	if err != nil {
		utils.InternalError(c, "Failed to list POCs")
		return
	}
	
	// Return in standard paginated format
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "success",
		"data":    result.POCs,
		"total":   result.Total,
		"page":    params.Page,
		"size":    params.PageSize,
	})
}

// TogglePOCEnabled godoc
// @Summary Toggle POC enabled status
// @Tags pocs
// @Accept json
// @Produce json
// @Param id path string true "POC ID"
// @Param enabled body object true "Enabled status"
// @Success 200 {object} map[string]string
// @Router /api/pocs/{id}/toggle [post]
func (h *POCHandler) TogglePOCEnabled(c *gin.Context) {
	id := c.Param("id")
	
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request body")
		return
	}
	
	if err := h.pocService.ToggleEnabled(id, req.Enabled); err != nil {
		utils.InternalError(c, "Failed to toggle POC status")
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "POC status updated successfully"})
}

// GetPOCStatistics godoc
// @Summary Get POC statistics
// @Tags pocs
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/pocs/statistics [get]
func (h *POCHandler) GetPOCStatistics(c *gin.Context) {
	stats, err := h.pocService.GetStatistics()
	if err != nil {
		utils.InternalError(c, "Failed to get POC statistics")
		return
	}
	
	c.JSON(http.StatusOK, stats)
}

// BatchDeletePOCs godoc
// @Summary Batch delete POCs
// @Tags pocs
// @Accept json
// @Produce json
// @Param ids body object true "POC IDs"
// @Success 200 {object} map[string]interface{}
// @Router /api/pocs/batch-delete [post]
func (h *POCHandler) BatchDeletePOCs(c *gin.Context) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequest(c, "Invalid request body")
		return
	}
	
	if len(req.IDs) == 0 {
		utils.BadRequest(c, "No POC IDs provided")
		return
	}
	
	deleted, failed := h.pocService.BatchDelete(req.IDs)
	
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "Batch delete completed",
		"data": gin.H{
			"deleted": deleted,
			"failed":  failed,
		},
	})
}

// ClearAllPOCs godoc
// @Summary Clear all POCs
// @Tags pocs
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/pocs/clear-all [delete]
func (h *POCHandler) ClearAllPOCs(c *gin.Context) {
	deleted, err := h.pocService.ClearAll()
	if err != nil {
		utils.InternalError(c, "Failed to clear POCs: "+err.Error())
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "All POCs cleared",
		"data": gin.H{
			"deleted": deleted,
		},
	})
}
