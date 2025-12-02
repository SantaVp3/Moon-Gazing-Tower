package service

import (
	"context"
	"errors"
	"time"

	"moongazing/database"
	"moongazing/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AssetService struct{}

func NewAssetService() *AssetService {
	return &AssetService{}
}

// CreateAsset creates a new asset
func (s *AssetService) CreateAsset(asset *models.Asset) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionAssets)
	
	asset.ID = primitive.NewObjectID()
	asset.CreatedAt = time.Now()
	asset.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, asset)
	if err != nil {
		return errors.New("创建资产失败")
	}
	
	return nil
}

// GetAssetByID retrieves asset by ID
func (s *AssetService) GetAssetByID(assetID string) (*models.Asset, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(assetID)
	if err != nil {
		return nil, errors.New("无效的资产ID")
	}
	
	collection := database.GetCollection(models.CollectionAssets)
	
	var asset models.Asset
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&asset)
	if err != nil {
		return nil, errors.New("资产不存在")
	}
	
	return &asset, nil
}

// ListAssets lists assets with filtering and pagination
func (s *AssetService) ListAssets(workspaceID string, assetType string, keyword string, tags []string, page, pageSize int) ([]*models.Asset, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionAssets)
	
	filter := bson.M{}
	
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	if assetType != "" {
		filter["type"] = assetType
	}
	
	if keyword != "" {
		filter["$or"] = []bson.M{
			{"value": bson.M{"$regex": keyword, "$options": "i"}},
			{"title": bson.M{"$regex": keyword, "$options": "i"}},
		}
	}
	
	if len(tags) > 0 {
		filter["tags"] = bson.M{"$all": tags}
	}
	
	// Get total count
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, errors.New("查询资产数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询资产列表失败")
	}
	defer cursor.Close(ctx)
	
	var assets []*models.Asset
	if err = cursor.All(ctx, &assets); err != nil {
		return nil, 0, errors.New("解析资产数据失败")
	}
	
	return assets, total, nil
}

// UpdateAsset updates an asset
func (s *AssetService) UpdateAsset(assetID string, updates map[string]interface{}) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(assetID)
	if err != nil {
		return errors.New("无效的资产ID")
	}
	
	collection := database.GetCollection(models.CollectionAssets)
	
	updates["updated_at"] = time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新资产失败")
	}
	
	return nil
}

// DeleteAsset deletes an asset
func (s *AssetService) DeleteAsset(assetID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(assetID)
	if err != nil {
		return errors.New("无效的资产ID")
	}
	
	collection := database.GetCollection(models.CollectionAssets)
	
	result, err := collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除资产失败")
	}
	
	if result.DeletedCount == 0 {
		return errors.New("资产不存在")
	}
	
	return nil
}

// BatchDeleteAssets deletes multiple assets
func (s *AssetService) BatchDeleteAssets(assetIDs []string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	var objIDs []primitive.ObjectID
	for _, id := range assetIDs {
		objID, err := primitive.ObjectIDFromHex(id)
		if err == nil {
			objIDs = append(objIDs, objID)
		}
	}
	
	collection := database.GetCollection(models.CollectionAssets)
	
	result, err := collection.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": objIDs}})
	if err != nil {
		return 0, errors.New("批量删除失败")
	}
	
	return result.DeletedCount, nil
}

// AddAssetTags adds tags to an asset
func (s *AssetService) AddAssetTags(assetID string, tags []string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(assetID)
	if err != nil {
		return errors.New("无效的资产ID")
	}
	
	collection := database.GetCollection(models.CollectionAssets)
	
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$addToSet": bson.M{"tags": bson.M{"$each": tags}},
		"$set":      bson.M{"updated_at": time.Now()},
	})
	if err != nil {
		return errors.New("添加标签失败")
	}
	
	return nil
}

// RemoveAssetTags removes tags from an asset
func (s *AssetService) RemoveAssetTags(assetID string, tags []string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(assetID)
	if err != nil {
		return errors.New("无效的资产ID")
	}
	
	collection := database.GetCollection(models.CollectionAssets)
	
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$pullAll": bson.M{"tags": tags},
		"$set":     bson.M{"updated_at": time.Now()},
	})
	if err != nil {
		return errors.New("移除标签失败")
	}
	
	return nil
}

// GetAssetStats returns asset statistics
func (s *AssetService) GetAssetStats(workspaceID string) (map[string]interface{}, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionAssets)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	// Count by type
	pipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id":   "$type",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, errors.New("统计失败")
	}
	defer cursor.Close(ctx)
	
	stats := make(map[string]interface{})
	stats["by_type"] = make(map[string]int)
	
	var results []struct {
		ID    string `bson:"_id"`
		Count int    `bson:"count"`
	}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, errors.New("解析统计数据失败")
	}
	
	total := 0
	typeStats := make(map[string]int)
	for _, r := range results {
		typeStats[r.ID] = r.Count
		total += r.Count
	}
	
	stats["by_type"] = typeStats
	stats["total"] = total
	
	return stats, nil
}

// CreateAssetGroup creates a new asset group
func (s *AssetService) CreateAssetGroup(group *models.AssetGroup) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionAssetGroups)
	
	group.ID = primitive.NewObjectID()
	group.CreatedAt = time.Now()
	group.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, group)
	if err != nil {
		return errors.New("创建资产组失败")
	}
	
	return nil
}

// ListAssetGroups lists asset groups
func (s *AssetService) ListAssetGroups(workspaceID string) ([]*models.AssetGroup, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionAssetGroups)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	cursor, err := collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, errors.New("查询资产组失败")
	}
	defer cursor.Close(ctx)
	
	var groups []*models.AssetGroup
	if err = cursor.All(ctx, &groups); err != nil {
		return nil, errors.New("解析资产组数据失败")
	}
	
	return groups, nil
}

// DeleteAssetGroup deletes an asset group
func (s *AssetService) DeleteAssetGroup(groupID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(groupID)
	if err != nil {
		return errors.New("无效的资产组ID")
	}
	
	collection := database.GetCollection(models.CollectionAssetGroups)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除资产组失败")
	}
	
	return nil
}

// CreateBlackWhiteList creates a blacklist or whitelist entry
func (s *AssetService) CreateBlackWhiteList(item *models.BlackWhiteList) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionBlackWhiteList)
	
	item.ID = primitive.NewObjectID()
	item.CreatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, item)
	if err != nil {
		return errors.New("创建黑白名单失败")
	}
	
	return nil
}

// ListBlackWhiteList lists blacklist or whitelist entries
func (s *AssetService) ListBlackWhiteList(workspaceID string, listType string, page, pageSize int) ([]*models.BlackWhiteList, int64, error) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionBlackWhiteList)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	if listType != "" {
		filter["type"] = listType
	}
	
	total, _ := collection.CountDocuments(ctx, filter)
	
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询黑白名单失败")
	}
	defer cursor.Close(ctx)
	
	var items []*models.BlackWhiteList
	if err = cursor.All(ctx, &items); err != nil {
		return nil, 0, errors.New("解析数据失败")
	}
	
	return items, total, nil
}

// DeleteBlackWhiteList deletes a blacklist or whitelist entry
func (s *AssetService) DeleteBlackWhiteList(itemID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(itemID)
	if err != nil {
		return errors.New("无效的ID")
	}
	
	collection := database.GetCollection(models.CollectionBlackWhiteList)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除失败")
	}
	
	return nil
}

// CheckBlackWhiteList checks if target is in blacklist or whitelist
func (s *AssetService) CheckBlackWhiteList(workspaceID string, target string) (bool, bool) {
	ctx, cancel := database.NewContext()
	defer cancel()
	
	collection := database.GetCollection(models.CollectionBlackWhiteList)
	
	filter := bson.M{"value": target}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	var item models.BlackWhiteList
	
	// Check blacklist
	filter["type"] = "black"
	err := collection.FindOne(ctx, filter).Decode(&item)
	if err == nil {
		return true, false // In blacklist
	}
	
	// Check whitelist
	filter["type"] = "white"
	err = collection.FindOne(ctx, filter).Decode(&item)
	if err == nil {
		return false, true // In whitelist
	}
	
	return false, false // Not in any list
}

// UpdateLastScanTime updates the last scan time of an asset
func (s *AssetService) UpdateLastScanTime(assetID string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(assetID)
	if err != nil {
		return errors.New("无效的资产ID")
	}

	collection := database.GetCollection(models.CollectionAssets)

	now := time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{
		"$set": bson.M{
			"last_scan_time": now,
			"updated_at":     now,
		},
	})
	if err != nil {
		return errors.New("更新扫描时间失败")
	}

	return nil
}

// UpdateLastScanTimeByValue updates the last scan time by asset value (target)
func (s *AssetService) UpdateLastScanTimeByValue(value string) error {
	ctx, cancel := database.NewContext()
	defer cancel()

	collection := database.GetCollection(models.CollectionAssets)

	now := time.Now()
	_, err := collection.UpdateOne(ctx, bson.M{"value": value}, bson.M{
		"$set": bson.M{
			"last_scan_time": now,
			"updated_at":     now,
		},
	})
	if err != nil {
		return errors.New("更新扫描时间失败")
	}

	return nil
}
