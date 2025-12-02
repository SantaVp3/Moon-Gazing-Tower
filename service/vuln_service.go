package service

import (
	"context"
	"errors"
	"time"

	"moongazing/database"
	"moongazing/models"
	"moongazing/scanner/vulnscan"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type VulnService struct{}

func NewVulnService() *VulnService {
	return &VulnService{}
}

// CreateVulnerability creates a new vulnerability
func (s *VulnService) CreateVulnerability(vuln *models.Vulnerability) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	vuln.ID = primitive.NewObjectID()
	vuln.Status = models.VulnStatusNew
	vuln.CreatedAt = time.Now()
	vuln.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, vuln)
	if err != nil {
		return errors.New("创建漏洞失败")
	}
	
	return nil
}

// GetVulnByID retrieves vulnerability by ID
func (s *VulnService) GetVulnByID(vulnID string) (*models.Vulnerability, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(vulnID)
	if err != nil {
		return nil, errors.New("无效的漏洞ID")
	}
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	var vuln models.Vulnerability
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&vuln)
	if err != nil {
		return nil, errors.New("漏洞不存在")
	}
	
	return &vuln, nil
}

// ListVulnerabilities lists vulnerabilities with filtering and pagination
func (s *VulnService) ListVulnerabilities(workspaceID string, severity string, status string, keyword string, page, pageSize int) ([]*models.Vulnerability, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	filter := bson.M{}
	
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	if severity != "" {
		filter["severity"] = severity
	}
	
	if status != "" {
		filter["status"] = status
	}
	
	if keyword != "" {
		filter["$or"] = []bson.M{
			{"name": bson.M{"$regex": keyword, "$options": "i"}},
			{"target": bson.M{"$regex": keyword, "$options": "i"}},
			{"description": bson.M{"$regex": keyword, "$options": "i"}},
		}
	}
	
	// Get total count
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, errors.New("查询漏洞数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{
			{Key: "severity", Value: 1},
			{Key: "created_at", Value: -1},
		})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询漏洞列表失败")
	}
	defer cursor.Close(ctx)
	
	var vulns []*models.Vulnerability
	if err = cursor.All(ctx, &vulns); err != nil {
		return nil, 0, errors.New("解析漏洞数据失败")
	}
	
	return vulns, total, nil
}

// UpdateVulnerability updates a vulnerability
func (s *VulnService) UpdateVulnerability(vulnID string, updates map[string]interface{}) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(vulnID)
	if err != nil {
		return errors.New("无效的漏洞ID")
	}
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	updates["updated_at"] = time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新漏洞失败")
	}
	
	return nil
}

// DeleteVulnerability deletes a vulnerability
func (s *VulnService) DeleteVulnerability(vulnID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(vulnID)
	if err != nil {
		return errors.New("无效的漏洞ID")
	}
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除漏洞失败")
	}
	
	return nil
}

// MarkAsFixed marks a vulnerability as fixed
func (s *VulnService) MarkAsFixed(vulnID string, fixedBy string) error {
	return s.UpdateVulnerability(vulnID, map[string]interface{}{
		"status":   models.VulnStatusFixed,
		"fixed_at": time.Now(),
		"fixed_by": fixedBy,
	})
}

// MarkAsIgnored marks a vulnerability as ignored
func (s *VulnService) MarkAsIgnored(vulnID string) error {
	return s.UpdateVulnerability(vulnID, map[string]interface{}{
		"status": models.VulnStatusIgnored,
	})
}

// MarkAsFalsePositive marks a vulnerability as false positive
func (s *VulnService) MarkAsFalsePositive(vulnID string) error {
	return s.UpdateVulnerability(vulnID, map[string]interface{}{
		"status": models.VulnStatusFalse,
	})
}

// GetVulnStats returns vulnerability statistics
func (s *VulnService) GetVulnStats(workspaceID string) (*models.ReportSummary, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	// Count by severity
	pipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id":   "$severity",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, errors.New("统计失败")
	}
	defer cursor.Close(ctx)
	
	var results []struct {
		ID    string `bson:"_id"`
		Count int    `bson:"count"`
	}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, errors.New("解析统计数据失败")
	}
	
	summary := &models.ReportSummary{}
	for _, r := range results {
		switch r.ID {
		case "critical":
			summary.CriticalCount = r.Count
		case "high":
			summary.HighCount = r.Count
		case "medium":
			summary.MediumCount = r.Count
		case "low":
			summary.LowCount = r.Count
		case "info":
			summary.InfoCount = r.Count
		}
		summary.TotalVulns += r.Count
	}
	
	return summary, nil
}

// CreatePOC creates a new POC
func (s *VulnService) CreatePOC(poc *models.POC) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionPOCs)
	
	poc.ID = primitive.NewObjectID()
	poc.Enabled = true
	poc.CreatedAt = time.Now()
	poc.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, poc)
	if err != nil {
		return errors.New("创建POC失败")
	}
	
	return nil
}

// GetPOCByID retrieves POC by ID
func (s *VulnService) GetPOCByID(pocID string) (*models.POC, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(pocID)
	if err != nil {
		return nil, errors.New("无效的POC ID")
	}
	
	collection := database.GetCollection(models.CollectionPOCs)
	
	var poc models.POC
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&poc)
	if err != nil {
		return nil, errors.New("POC不存在")
	}
	
	return &poc, nil
}

// ListPOCs lists POCs with filtering and pagination
func (s *VulnService) ListPOCs(pocType string, severity string, tags []string, keyword string, page, pageSize int) ([]*models.POC, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionPOCs)
	
	filter := bson.M{}
	
	if pocType != "" {
		filter["type"] = pocType
	}
	
	if severity != "" {
		filter["severity"] = severity
	}
	
	if len(tags) > 0 {
		filter["tags"] = bson.M{"$all": tags}
	}
	
	if keyword != "" {
		filter["$or"] = []bson.M{
			{"name": bson.M{"$regex": keyword, "$options": "i"}},
			{"description": bson.M{"$regex": keyword, "$options": "i"}},
		}
	}
	
	// Get total count
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, errors.New("查询POC数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "name", Value: 1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询POC列表失败")
	}
	defer cursor.Close(ctx)
	
	var pocs []*models.POC
	if err = cursor.All(ctx, &pocs); err != nil {
		return nil, 0, errors.New("解析POC数据失败")
	}
	
	return pocs, total, nil
}

// UpdatePOC updates a POC
func (s *VulnService) UpdatePOC(pocID string, updates map[string]interface{}) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(pocID)
	if err != nil {
		return errors.New("无效的POC ID")
	}
	
	collection := database.GetCollection(models.CollectionPOCs)
	
	updates["updated_at"] = time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新POC失败")
	}
	
	return nil
}

// DeletePOC deletes a POC
func (s *VulnService) DeletePOC(pocID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(pocID)
	if err != nil {
		return errors.New("无效的POC ID")
	}
	
	collection := database.GetCollection(models.CollectionPOCs)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除POC失败")
	}
	
	return nil
}

// TogglePOC enables or disables a POC
func (s *VulnService) TogglePOC(pocID string, enabled bool) error {
	return s.UpdatePOC(pocID, map[string]interface{}{
		"enabled": enabled,
	})
}

// CreateReport creates a vulnerability report
func (s *VulnService) CreateReport(report *models.VulnReport) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnReports)
	
	report.ID = primitive.NewObjectID()
	report.CreatedAt = time.Now()
	
	// Get vulnerability statistics
	stats, _ := s.GetVulnStats(report.WorkspaceID.Hex())
	if stats != nil {
		report.Summary = *stats
	}
	
	_, err := collection.InsertOne(ctx, report)
	if err != nil {
		return errors.New("创建报告失败")
	}
	
	return nil
}

// ListReports lists vulnerability reports
func (s *VulnService) ListReports(workspaceID string, page, pageSize int) ([]*models.VulnReport, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnReports)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	total, _ := collection.CountDocuments(ctx, filter)
	
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询报告失败")
	}
	defer cursor.Close(ctx)
	
	var reports []*models.VulnReport
	if err = cursor.All(ctx, &reports); err != nil {
		return nil, 0, errors.New("解析报告数据失败")
	}
	
	return reports, total, nil
}

// GetReportByID gets a report by ID
func (s *VulnService) GetReportByID(reportID string) (*models.VulnReport, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		return nil, errors.New("无效的报告ID")
	}
	
	collection := database.GetCollection(models.CollectionVulnReports)
	
	var report models.VulnReport
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&report)
	if err != nil {
		return nil, errors.New("报告不存在")
	}
	
	return &report, nil
}

// DeleteReport deletes a report
func (s *VulnService) DeleteReport(reportID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		return errors.New("无效的报告ID")
	}
	
	collection := database.GetCollection(models.CollectionVulnReports)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除报告失败")
	}
	
	return nil
}

// VulnStatistics 漏洞统计数据
type VulnStatistics struct {
	Total           int64             `json:"total"`
	BySeverity      map[string]int64  `json:"by_severity"`
	ByStatus        map[string]int64  `json:"by_status"`
	ByType          map[string]int64  `json:"by_type"`
	RecentVulns     []*models.Vulnerability `json:"recent_vulns"`
	TrendData       []TrendDataPoint  `json:"trend_data"`
}

// TrendDataPoint 趋势数据点
type TrendDataPoint struct {
	Date     string `json:"date"`
	Critical int64  `json:"critical"`
	High     int64  `json:"high"`
	Medium   int64  `json:"medium"`
	Low      int64  `json:"low"`
	Info     int64  `json:"info"`
}

// GetVulnStatistics 获取漏洞统计数据
func (s *VulnService) GetVulnStatistics(workspaceID string) (*VulnStatistics, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	stats := &VulnStatistics{
		BySeverity: make(map[string]int64),
		ByStatus:   make(map[string]int64),
		ByType:     make(map[string]int64),
	}
	
	// 总数
	total, _ := collection.CountDocuments(ctx, filter)
	stats.Total = total
	
	// 按严重程度统计
	severityPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{"_id": "$severity", "count": bson.M{"$sum": 1}}},
	}
	cursor, err := collection.Aggregate(ctx, severityPipeline)
	if err == nil {
		var results []struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		cursor.All(ctx, &results)
		for _, r := range results {
			stats.BySeverity[r.ID] = r.Count
		}
		cursor.Close(ctx)
	}
	
	// 按状态统计
	statusPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{"_id": "$status", "count": bson.M{"$sum": 1}}},
	}
	cursor, err = collection.Aggregate(ctx, statusPipeline)
	if err == nil {
		var results []struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		cursor.All(ctx, &results)
		for _, r := range results {
			stats.ByStatus[r.ID] = r.Count
		}
		cursor.Close(ctx)
	}
	
	// 按类型统计
	typePipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{"_id": "$type", "count": bson.M{"$sum": 1}}},
	}
	cursor, err = collection.Aggregate(ctx, typePipeline)
	if err == nil {
		var results []struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		cursor.All(ctx, &results)
		for _, r := range results {
			if r.ID != "" {
				stats.ByType[r.ID] = r.Count
			}
		}
		cursor.Close(ctx)
	}
	
	// 最近漏洞
	opts := options.Find().
		SetLimit(10).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err = collection.Find(ctx, filter, opts)
	if err == nil {
		cursor.All(ctx, &stats.RecentVulns)
		cursor.Close(ctx)
	}
	
	// 趋势数据（最近30天）
	stats.TrendData = s.getVulnTrendData(ctx, filter, 30)
	
	return stats, nil
}

// getVulnTrendData 获取漏洞趋势数据
func (s *VulnService) getVulnTrendData(ctx context.Context, filter bson.M, days int) []TrendDataPoint {
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	endDate := time.Now()
	startDate := endDate.AddDate(0, 0, -days)
	
	// 添加日期过滤
	dateFilter := bson.M{
		"created_at": bson.M{
			"$gte": startDate,
			"$lte": endDate,
		},
	}
	for k, v := range filter {
		dateFilter[k] = v
	}
	
	pipeline := []bson.M{
		{"$match": dateFilter},
		{"$group": bson.M{
			"_id": bson.M{
				"date":     bson.M{"$dateToString": bson.M{"format": "%Y-%m-%d", "date": "$created_at"}},
				"severity": "$severity",
			},
			"count": bson.M{"$sum": 1},
		}},
		{"$sort": bson.M{"_id.date": 1}},
	}
	
	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil
	}
	defer cursor.Close(ctx)
	
	var results []struct {
		ID struct {
			Date     string `bson:"date"`
			Severity string `bson:"severity"`
		} `bson:"_id"`
		Count int64 `bson:"count"`
	}
	cursor.All(ctx, &results)
	
	// 按日期聚合
	dateMap := make(map[string]*TrendDataPoint)
	for _, r := range results {
		if _, exists := dateMap[r.ID.Date]; !exists {
			dateMap[r.ID.Date] = &TrendDataPoint{Date: r.ID.Date}
		}
		switch r.ID.Severity {
		case "critical":
			dateMap[r.ID.Date].Critical = r.Count
		case "high":
			dateMap[r.ID.Date].High = r.Count
		case "medium":
			dateMap[r.ID.Date].Medium = r.Count
		case "low":
			dateMap[r.ID.Date].Low = r.Count
		case "info":
			dateMap[r.ID.Date].Info = r.Count
		}
	}
	
	// 转为数组
	var trendData []TrendDataPoint
	for i := 0; i <= days; i++ {
		date := startDate.AddDate(0, 0, i).Format("2006-01-02")
		if point, exists := dateMap[date]; exists {
			trendData = append(trendData, *point)
		} else {
			trendData = append(trendData, TrendDataPoint{Date: date})
		}
	}
	
	return trendData
}

// VerifyVulnerability 验证漏洞（重新扫描）
func (s *VulnService) VerifyVulnerability(vulnID string) (*models.Vulnerability, bool, error) {
	// 获取漏洞信息
	vuln, err := s.GetVulnByID(vulnID)
	if err != nil {
		return nil, false, err
	}
	
	verified := false
	
	// 使用 Nuclei CLI 扫描器重新验证
	if vulnscan.GlobalNucleiScanner != nil && vulnscan.GlobalNucleiScanner.IsAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		
		// 尝试使用原始模板 ID 验证
		templateID := vuln.TemplateID
		if templateID == "" {
			templateID = vuln.Type // 退回使用漏洞类型
		}
		
		if templateID != "" && vuln.Target != "" {
			result, err := vulnscan.GlobalNucleiScanner.VerifyVulnerability(ctx, vuln.Target, templateID)
			if err == nil && result != nil {
				verified = true
			}
		}
	}
	
	// 更新验证时间和状态
	updateData := map[string]interface{}{
		"last_verified_at": time.Now(),
	}
	if verified {
		updateData["status"] = models.VulnStatusConfirmed
	}
	s.UpdateVulnerability(vulnID, updateData)
	
	// 重新获取更新后的漏洞信息
	vuln, _ = s.GetVulnByID(vulnID)
	
	return vuln, verified, nil
}

// BatchUpdateStatus 批量更新状态
func (s *VulnService) BatchUpdateStatus(vulnIDs []string, status models.VulnStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	var objectIDs []primitive.ObjectID
	for _, id := range vulnIDs {
		objID, err := primitive.ObjectIDFromHex(id)
		if err == nil {
			objectIDs = append(objectIDs, objID)
		}
	}
	
	if len(objectIDs) == 0 {
		return errors.New("无有效的漏洞ID")
	}
	
	update := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now(),
		},
	}
	
	_, err := collection.UpdateMany(ctx, bson.M{"_id": bson.M{"$in": objectIDs}}, update)
	if err != nil {
		return errors.New("批量更新失败")
	}
	
	return nil
}

// GetVulnsByTaskID 根据任务ID获取漏洞
func (s *VulnService) GetVulnsByTaskID(taskID string, page, pageSize int) ([]*models.Vulnerability, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, errors.New("无效的任务ID")
	}
	
	collection := database.GetCollection(models.CollectionVulnerabilities)
	
	filter := bson.M{"task_id": objID}
	
	total, _ := collection.CountDocuments(ctx, filter)
	
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "severity", Value: 1}, {Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询漏洞失败")
	}
	defer cursor.Close(ctx)
	
	var vulns []*models.Vulnerability
	cursor.All(ctx, &vulns)
	
	return vulns, total, nil
}
