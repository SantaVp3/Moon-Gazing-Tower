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

type PluginService struct{}

func NewPluginService() *PluginService {
	return &PluginService{}
}

// CreatePlugin creates a new plugin
func (s *PluginService) CreatePlugin(plugin *models.Plugin) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionPlugins)
	
	// Check if plugin name already exists
	var existing models.Plugin
	err := collection.FindOne(ctx, bson.M{"name": plugin.Name}).Decode(&existing)
	if err == nil {
		return errors.New("插件名称已存在")
	}
	
	plugin.ID = primitive.NewObjectID()
	plugin.Installed = true
	plugin.Enabled = true
	plugin.CreatedAt = time.Now()
	plugin.UpdatedAt = time.Now()
	
	_, err = collection.InsertOne(ctx, plugin)
	if err != nil {
		return errors.New("创建插件失败")
	}
	
	return nil
}

// GetPluginByID retrieves plugin by ID
func (s *PluginService) GetPluginByID(pluginID string) (*models.Plugin, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(pluginID)
	if err != nil {
		return nil, errors.New("无效的插件ID")
	}
	
	collection := database.GetCollection(models.CollectionPlugins)
	
	var plugin models.Plugin
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&plugin)
	if err != nil {
		return nil, errors.New("插件不存在")
	}
	
	return &plugin, nil
}

// ListPlugins lists plugins with filtering and pagination
func (s *PluginService) ListPlugins(pluginType string, language string, enabled *bool, keyword string, page, pageSize int) ([]*models.Plugin, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionPlugins)
	
	filter := bson.M{}
	
	if pluginType != "" {
		filter["type"] = pluginType
	}
	
	if language != "" {
		filter["language"] = language
	}
	
	if enabled != nil {
		filter["enabled"] = *enabled
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
		return nil, 0, errors.New("查询插件数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "name", Value: 1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询插件列表失败")
	}
	defer cursor.Close(ctx)
	
	var plugins []*models.Plugin
	if err = cursor.All(ctx, &plugins); err != nil {
		return nil, 0, errors.New("解析插件数据失败")
	}
	
	return plugins, total, nil
}

// UpdatePlugin updates a plugin
func (s *PluginService) UpdatePlugin(pluginID string, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(pluginID)
	if err != nil {
		return errors.New("无效的插件ID")
	}
	
	collection := database.GetCollection(models.CollectionPlugins)
	
	updates["updated_at"] = time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新插件失败")
	}
	
	return nil
}

// DeletePlugin deletes a plugin
func (s *PluginService) DeletePlugin(pluginID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(pluginID)
	if err != nil {
		return errors.New("无效的插件ID")
	}
	
	collection := database.GetCollection(models.CollectionPlugins)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除插件失败")
	}
	
	return nil
}

// TogglePlugin enables or disables a plugin
func (s *PluginService) TogglePlugin(pluginID string, enabled bool) error {
	return s.UpdatePlugin(pluginID, map[string]interface{}{
		"enabled": enabled,
	})
}

// InstallPlugin installs a plugin
func (s *PluginService) InstallPlugin(pluginID string) error {
	return s.UpdatePlugin(pluginID, map[string]interface{}{
		"installed": true,
	})
}

// UninstallPlugin uninstalls a plugin
func (s *PluginService) UninstallPlugin(pluginID string) error {
	return s.UpdatePlugin(pluginID, map[string]interface{}{
		"installed": false,
		"enabled":   false,
	})
}

// CreateFingerprintRule creates a fingerprint rule
func (s *PluginService) CreateFingerprintRule(rule *models.FingerprintRule) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionFingerprintRules)
	
	rule.ID = primitive.NewObjectID()
	rule.Enabled = true
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, rule)
	if err != nil {
		return errors.New("创建指纹规则失败")
	}
	
	return nil
}

// ListFingerprintRules lists fingerprint rules
func (s *PluginService) ListFingerprintRules(category string, keyword string, page, pageSize int) ([]*models.FingerprintRule, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionFingerprintRules)
	
	filter := bson.M{}
	
	if category != "" {
		filter["category"] = category
	}
	
	if keyword != "" {
		filter["name"] = bson.M{"$regex": keyword, "$options": "i"}
	}
	
	total, _ := collection.CountDocuments(ctx, filter)
	
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "name", Value: 1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询指纹规则失败")
	}
	defer cursor.Close(ctx)
	
	var rules []*models.FingerprintRule
	if err = cursor.All(ctx, &rules); err != nil {
		return nil, 0, errors.New("解析指纹规则数据失败")
	}
	
	return rules, total, nil
}

// DeleteFingerprintRule deletes a fingerprint rule
func (s *PluginService) DeleteFingerprintRule(ruleID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(ruleID)
	if err != nil {
		return errors.New("无效的规则ID")
	}
	
	collection := database.GetCollection(models.CollectionFingerprintRules)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除规则失败")
	}
	
	return nil
}

// CreateDictionary creates a dictionary
func (s *PluginService) CreateDictionary(dict *models.Dictionary) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionDictionaries)
	
	dict.ID = primitive.NewObjectID()
	dict.CreatedAt = time.Now()
	dict.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, dict)
	if err != nil {
		return errors.New("创建字典失败")
	}
	
	return nil
}

// ListDictionaries lists dictionaries
func (s *PluginService) ListDictionaries(dictType string, page, pageSize int) ([]*models.Dictionary, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionDictionaries)
	
	filter := bson.M{}
	
	if dictType != "" {
		filter["type"] = dictType
	}
	
	total, _ := collection.CountDocuments(ctx, filter)
	
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "name", Value: 1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询字典失败")
	}
	defer cursor.Close(ctx)
	
	var dicts []*models.Dictionary
	if err = cursor.All(ctx, &dicts); err != nil {
		return nil, 0, errors.New("解析字典数据失败")
	}
	
	return dicts, total, nil
}

// DeleteDictionary deletes a dictionary
func (s *PluginService) DeleteDictionary(dictID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(dictID)
	if err != nil {
		return errors.New("无效的字典ID")
	}
	
	collection := database.GetCollection(models.CollectionDictionaries)
	
	// Check if it's a builtin dictionary
	var dict models.Dictionary
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&dict)
	if err == nil && dict.IsBuiltin {
		return errors.New("不能删除内置字典")
	}
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除字典失败")
	}
	
	return nil
}
