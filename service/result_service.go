package service

import (
	"context"
	"moongazing/database"
	"moongazing/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ResultService struct {
	collection *mongo.Collection
}

func NewResultService() *ResultService {
	return &ResultService{
		collection: database.GetCollection(models.CollectionScanResults),
	}
}

// CreateResult 创建扫描结果
func (s *ResultService) CreateResult(result *models.ScanResult) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	result.CreatedAt = time.Now()
	result.UpdatedAt = time.Now()

	res, err := s.collection.InsertOne(ctx, result)
	if err != nil {
		return err
	}

	result.ID = res.InsertedID.(primitive.ObjectID)
	return nil
}

// CreateResultWithDedup 创建扫描结果（带去重）
// 根据 type 和 data 中的关键字段进行去重
func (s *ResultService) CreateResultWithDedup(result *models.ScanResult) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	// 构建去重过滤条件
	filter := bson.M{
		"task_id": result.TaskID,
		"type":    result.Type,
	}

	// 根据不同类型添加特定的去重字段
	switch result.Type {
	case models.ResultTypeSubdomain:
		if subdomain, ok := result.Data["subdomain"].(string); ok && subdomain != "" {
			filter["data.subdomain"] = subdomain
		}
	case models.ResultTypePort:
		if ip, ok := result.Data["ip"].(string); ok && ip != "" {
			filter["data.ip"] = ip
		}
		if port, ok := result.Data["port"]; ok {
			filter["data.port"] = port
		}
	case models.ResultTypeURL, models.ResultTypeCrawler:
		if url, ok := result.Data["url"].(string); ok && url != "" {
			filter["data.url"] = url
		}
	case models.ResultTypeDirScan:
		if url, ok := result.Data["url"].(string); ok && url != "" {
			filter["data.url"] = url
		}
	case models.ResultTypeVuln:
		if vulnID, ok := result.Data["vuln_id"].(string); ok && vulnID != "" {
			filter["data.vuln_id"] = vulnID
		}
		if target, ok := result.Data["target"].(string); ok && target != "" {
			filter["data.target"] = target
		}
	case models.ResultTypeSensitive:
		if url, ok := result.Data["url"].(string); ok && url != "" {
			filter["data.url"] = url
		}
		if matchType, ok := result.Data["type"].(string); ok && matchType != "" {
			filter["data.type"] = matchType
		}
	}

	// 使用 Upsert：存在则更新，不存在则插入
	result.UpdatedAt = time.Now()
	
	update := bson.M{
		"$set": bson.M{
			"data":       result.Data,
			"source":     result.Source,
			"tags":       result.Tags,
			"project":    result.Project,
			"updated_at": result.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"task_id":      result.TaskID,
			"workspace_id": result.WorkspaceID,
			"type":         result.Type,
			"created_at":   time.Now(),
		},
	}

	opts := options.Update().SetUpsert(true)
	_, err := s.collection.UpdateOne(ctx, filter, update, opts)
	return err
}

// BatchCreateResults 批量创建扫描结果
func (s *ResultService) BatchCreateResults(results []models.ScanResult) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	docs := make([]interface{}, len(results))
	now := time.Now()
	for i := range results {
		results[i].CreatedAt = now
		results[i].UpdatedAt = now
		docs[i] = results[i]
	}

	_, err := s.collection.InsertMany(ctx, docs)
	return err
}

// BatchCreateResultsWithDedup 批量创建扫描结果（带去重）
func (s *ResultService) BatchCreateResultsWithDedup(results []models.ScanResult) (int, int, error) {
	inserted := 0
	skipped := 0
	
	for i := range results {
		err := s.CreateResultWithDedup(&results[i])
		if err != nil {
			skipped++
		} else {
			inserted++
		}
	}
	
	return inserted, skipped, nil
}

// GetResultsByTask 获取任务的扫描结果
func (s *ResultService) GetResultsByTask(taskID string, resultType models.ResultType, page, pageSize int, search string, statusCode int) ([]models.ScanResult, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, err
	}

	filter := bson.M{"task_id": objID}
	if resultType != "" {
		filter["type"] = resultType
	}
	
	// 状态码筛选（主要用于目录扫描结果）
	if statusCode > 0 {
		filter["data.status"] = statusCode
	}
	
	if search != "" {
		// 根据不同类型搜索不同字段
		filter["$or"] = []bson.M{
			{"data.domain": bson.M{"$regex": search, "$options": "i"}},
			{"data.subdomain": bson.M{"$regex": search, "$options": "i"}},
			{"data.url": bson.M{"$regex": search, "$options": "i"}},
			{"data.ip": bson.M{"$regex": search, "$options": "i"}},
			{"data.company": bson.M{"$regex": search, "$options": "i"}},
			{"project": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// 计算总数
	total, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	skip := int64((page - 1) * pageSize)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []models.ScanResult
	if err = cursor.All(ctx, &results); err != nil {
		return nil, 0, err
	}

	return results, total, nil
}

// GetResultStats 获取任务结果统计
func (s *ResultService) GetResultStats(taskID string) (map[string]int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, err
	}

	pipeline := []bson.M{
		{"$match": bson.M{"task_id": objID}},
		{"$group": bson.M{
			"_id":   "$type",
			"count": bson.M{"$sum": 1},
		}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	stats := make(map[string]int64)
	for cursor.Next(ctx) {
		var result struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cursor.Decode(&result); err != nil {
			continue
		}
		stats[result.ID] = result.Count
	}

	return stats, nil
}

// DeleteResultsByTask 删除任务的所有结果
func (s *ResultService) DeleteResultsByTask(taskID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return err
	}

	_, err = s.collection.DeleteMany(ctx, bson.M{"task_id": objID})
	return err
}

// UpdateResultTags 更新结果标签
func (s *ResultService) UpdateResultTags(id string, tags []string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$set": bson.M{
			"tags":       tags,
			"updated_at": time.Now(),
		},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// AddResultTag 添加标签
func (s *ResultService) AddResultTag(id string, tag string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$addToSet": bson.M{"tags": tag},
		"$set":      bson.M{"updated_at": time.Now()},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// RemoveResultTag 移除标签
func (s *ResultService) RemoveResultTag(id string, tag string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	update := bson.M{
		"$pull": bson.M{"tags": tag},
		"$set":  bson.M{"updated_at": time.Now()},
	}

	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	return err
}

// ExportResults 导出结果 (返回所有匹配的结果，不分页)
func (s *ResultService) ExportResults(taskID string, resultType models.ResultType) ([]models.ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{"task_id": objID}
	if resultType != "" {
		filter["type"] = resultType
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.ScanResult
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

// BatchDeleteResults 批量删除结果
func (s *ResultService) BatchDeleteResults(ids []string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objIDs := make([]primitive.ObjectID, 0, len(ids))
	for _, id := range ids {
		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			continue
		}
		objIDs = append(objIDs, objID)
	}

	if len(objIDs) == 0 {
		return nil
	}

	_, err := s.collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": objIDs}})
	return err
}

// GetSubdomainResults 获取子域名结果 (带解析)
func (s *ResultService) GetSubdomainResults(taskID string, page, pageSize int, search string) ([]map[string]interface{}, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, err
	}

	filter := bson.M{
		"task_id": objID,
		"type":    models.ResultTypeSubdomain,
	}
	if search != "" {
		filter["$or"] = []bson.M{
			{"data.subdomain": bson.M{"$regex": search, "$options": "i"}},
			{"data.domain": bson.M{"$regex": search, "$options": "i"}},
			{"data.title": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	total, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	skip := int64((page - 1) * pageSize)
	opts := options.Find().
		SetSkip(skip).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)

	var results []map[string]interface{}
	for cursor.Next(ctx) {
		var result models.ScanResult
		if err := cursor.Decode(&result); err != nil {
			continue
		}

		item := map[string]interface{}{
			"id":         result.ID.Hex(),
			"task_id":    result.TaskID.Hex(),
			"type":       result.Type,
			"tags":       result.Tags,
			"project":    result.Project,
			"created_at": result.CreatedAt,
		}

		// 解析 data 字段 (Data 已经是 bson.M 类型)
		for k, v := range result.Data {
			item[k] = v
		}

		results = append(results, item)
	}

	return results, total, nil
}
