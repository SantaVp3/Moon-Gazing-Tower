package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
)

type SensitiveRuleHandler struct{}

func NewSensitiveRuleHandler() *SensitiveRuleHandler {
	return &SensitiveRuleHandler{}
}

// CreateSensitiveRuleRequest 创建规则请求
type CreateSensitiveRuleRequest struct {
	Name        string                       `json:"name" binding:"required"`
	Type        models.SensitiveRuleType     `json:"type" binding:"required"`
	Pattern     string                       `json:"pattern" binding:"required"`
	Description string                       `json:"description"`
	Severity    models.SensitiveRuleSeverity `json:"severity" binding:"required"`
	Category    string                       `json:"category"`
	Example     string                       `json:"example"`
	IsEnabled   bool                         `json:"is_enabled"`
}

// UpdateSensitiveRuleRequest 更新规则请求
type UpdateSensitiveRuleRequest struct {
	Name        string                       `json:"name"`
	Type        models.SensitiveRuleType     `json:"type"`
	Pattern     string                       `json:"pattern"`
	Description string                       `json:"description"`
	Severity    models.SensitiveRuleSeverity `json:"severity"`
	Category    string                       `json:"category"`
	Example     string                       `json:"example"`
	IsEnabled   *bool                        `json:"is_enabled"`
}

// ListSensitiveRules 获取规则列表
func (h *SensitiveRuleHandler) ListSensitiveRules(c *gin.Context) {
	category := c.Query("category")
	severity := c.Query("severity")
	isEnabled := c.Query("is_enabled")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	query := database.DB.Model(&models.SensitiveRule{})

	// 筛选条件
	if category != "" {
		query = query.Where("category = ?", category)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if isEnabled != "" {
		enabled := isEnabled == "true"
		query = query.Where("is_enabled = ?", enabled)
	}

	// 统计总数
	var total int64
	query.Count(&total)

	// 分页查询
	var rules []models.SensitiveRule
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&rules).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules":       rules,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// GetSensitiveRule 获取单个规则
func (h *SensitiveRuleHandler) GetSensitiveRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule models.SensitiveRule
	if err := database.DB.First(&rule, "id = ?", ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

// CreateSensitiveRule 创建规则
func (h *SensitiveRuleHandler) CreateSensitiveRule(c *gin.Context) {
	var req CreateSensitiveRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("userID")

	rule := &models.SensitiveRule{
		Name:        req.Name,
		Type:        req.Type,
		Pattern:     req.Pattern,
		Description: req.Description,
		Severity:    req.Severity,
		Category:    req.Category,
		Example:     req.Example,
		IsEnabled:   req.IsEnabled,
		IsBuiltIn:   false,
		MatchCount:  0,
		CreatedBy:   userID,
	}

	if err := database.DB.Create(rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Rule created successfully",
		"rule":    rule,
	})
}

// UpdateSensitiveRule 更新规则
func (h *SensitiveRuleHandler) UpdateSensitiveRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule models.SensitiveRule
	if err := database.DB.First(&rule, "id = ?", ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// 内置规则不允许修改核心字段
	if rule.IsBuiltIn {
		c.JSON(http.StatusForbidden, gin.H{"error": "Built-in rules cannot be modified"})
		return
	}

	var req UpdateSensitiveRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Type != "" {
		rule.Type = req.Type
	}
	if req.Pattern != "" {
		rule.Pattern = req.Pattern
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	if req.Severity != "" {
		rule.Severity = req.Severity
	}
	if req.Category != "" {
		rule.Category = req.Category
	}
	if req.Example != "" {
		rule.Example = req.Example
	}
	if req.IsEnabled != nil {
		rule.IsEnabled = *req.IsEnabled
	}

	if err := database.DB.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule updated successfully",
		"rule":    rule,
	})
}

// DeleteSensitiveRule 删除规则
func (h *SensitiveRuleHandler) DeleteSensitiveRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule models.SensitiveRule
	if err := database.DB.First(&rule, "id = ?", ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// 内置规则不允许删除
	if rule.IsBuiltIn {
		c.JSON(http.StatusForbidden, gin.H{"error": "Built-in rules cannot be deleted"})
		return
	}

	if err := database.DB.Delete(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// ToggleSensitiveRule 切换规则启用状态
func (h *SensitiveRuleHandler) ToggleSensitiveRule(c *gin.Context) {
	ruleID := c.Param("id")

	var rule models.SensitiveRule
	if err := database.DB.First(&rule, "id = ?", ruleID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	rule.IsEnabled = !rule.IsEnabled

	if err := database.DB.Save(&rule).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Rule status toggled successfully",
		"is_enabled": rule.IsEnabled,
		"rule":       rule,
	})
}

// BatchDeleteSensitiveRules 批量删除规则
func (h *SensitiveRuleHandler) BatchDeleteSensitiveRules(c *gin.Context) {
	var req struct {
		RuleIDs []string `json:"rule_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查是否包含内置规则
	var builtInCount int64
	database.DB.Model(&models.SensitiveRule{}).
		Where("id IN ? AND is_built_in = ?", req.RuleIDs, true).
		Count(&builtInCount)

	if builtInCount > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete built-in rules"})
		return
	}

	// 批量删除
	if err := database.DB.Where("id IN ?", req.RuleIDs).Delete(&models.SensitiveRule{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rules deleted successfully",
		"count":   len(req.RuleIDs),
	})
}

// BatchToggleSensitiveRules 批量切换规则状态
func (h *SensitiveRuleHandler) BatchToggleSensitiveRules(c *gin.Context) {
	var req struct {
		RuleIDs   []string `json:"rule_ids" binding:"required"`
		IsEnabled bool     `json:"is_enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := database.DB.Model(&models.SensitiveRule{}).
		Where("id IN ?", req.RuleIDs).
		Update("is_enabled", req.IsEnabled).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Rules status updated successfully",
		"count":      len(req.RuleIDs),
		"is_enabled": req.IsEnabled,
	})
}

// GetSensitiveRuleStats 获取规则统计
func (h *SensitiveRuleHandler) GetSensitiveRuleStats(c *gin.Context) {
	var stats struct {
		TotalRules   int64 `json:"total_rules"`
		EnabledRules int64 `json:"enabled_rules"`
		BuiltInRules int64 `json:"built_in_rules"`
		TotalMatches int64 `json:"total_matches"`
	}

	database.DB.Model(&models.SensitiveRule{}).Count(&stats.TotalRules)
	database.DB.Model(&models.SensitiveRule{}).Where("is_enabled = ?", true).Count(&stats.EnabledRules)
	database.DB.Model(&models.SensitiveRule{}).Where("is_built_in = ?", true).Count(&stats.BuiltInRules)
	database.DB.Model(&models.SensitiveMatch{}).Count(&stats.TotalMatches)

	c.JSON(http.StatusOK, stats)
}

// ListSensitiveMatches 获取匹配记录
func (h *SensitiveRuleHandler) ListSensitiveMatches(c *gin.Context) {
	taskID := c.Query("task_id")
	ruleID := c.Query("rule_id")
	severity := c.Query("severity")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	query := database.DB.Model(&models.SensitiveMatch{})

	if taskID != "" {
		query = query.Where("task_id = ?", taskID)
	}
	if ruleID != "" {
		query = query.Where("rule_id = ?", ruleID)
	}
	if severity != "" {
		query = query.Where("severity = ?", severity)
	}

	var total int64
	query.Count(&total)

	var matches []models.SensitiveMatch
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&matches).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch matches"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"matches":     matches,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}
