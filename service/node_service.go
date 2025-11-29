package service

import (
	"context"
	"errors"
	"time"

	"moongazing/database"
	"moongazing/models"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type NodeService struct{}

func NewNodeService() *NodeService {
	return &NodeService{}
}

// RegisterNode registers a new scanner node
func (s *NodeService) RegisterNode(node *models.ScannerNode) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	// Check if node already exists
	var existingNode models.ScannerNode
	err := collection.FindOne(ctx, bson.M{"node_id": node.NodeID}).Decode(&existingNode)
	if err == nil {
		// Update existing node
		return s.UpdateNode(existingNode.ID.Hex(), map[string]interface{}{
			"status":         models.NodeStatusOnline,
			"ip":             node.IP,
			"port":           node.Port,
			"version":        node.Version,
			"capabilities":   node.Capabilities,
			"max_tasks":      node.MaxTasks,
			"system_info":    node.SystemInfo,
			"last_heartbeat": time.Now(),
		})
	}
	
	node.ID = primitive.NewObjectID()
	if node.NodeID == "" {
		node.NodeID = uuid.New().String()
	}
	node.Status = models.NodeStatusOnline
	node.LastHeartbeat = time.Now()
	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()
	
	_, err = collection.InsertOne(ctx, node)
	if err != nil {
		return errors.New("注册节点失败")
	}
	
	return nil
}

// GetNodeByID retrieves node by ID
func (s *NodeService) GetNodeByID(nodeID string) (*models.ScannerNode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	var node models.ScannerNode
	
	// Try ObjectID first
	objID, err := primitive.ObjectIDFromHex(nodeID)
	if err == nil {
		err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&node)
		if err == nil {
			return &node, nil
		}
	}
	
	// Try node_id
	err = collection.FindOne(ctx, bson.M{"node_id": nodeID}).Decode(&node)
	if err != nil {
		return nil, errors.New("节点不存在")
	}
	
	return &node, nil
}

// ListNodes lists all scanner nodes
func (s *NodeService) ListNodes(nodeType string, status string, page, pageSize int) ([]*models.ScannerNode, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	filter := bson.M{}
	
	if nodeType != "" {
		filter["type"] = nodeType
	}
	
	if status != "" {
		filter["status"] = status
	}
	
	// Get total count
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, errors.New("查询节点数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询节点列表失败")
	}
	defer cursor.Close(ctx)
	
	var nodes []*models.ScannerNode
	if err = cursor.All(ctx, &nodes); err != nil {
		return nil, 0, errors.New("解析节点数据失败")
	}
	
	return nodes, total, nil
}

// UpdateNode updates a node
func (s *NodeService) UpdateNode(nodeID string, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	updates["updated_at"] = time.Now()
	
	// Try ObjectID first
	objID, err := primitive.ObjectIDFromHex(nodeID)
	if err == nil {
		_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
		if err == nil {
			return nil
		}
	}
	
	// Try node_id
	_, err = collection.UpdateOne(ctx, bson.M{"node_id": nodeID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新节点失败")
	}
	
	return nil
}

// DeleteNode deletes a node
func (s *NodeService) DeleteNode(nodeID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	// Try ObjectID first
	objID, err := primitive.ObjectIDFromHex(nodeID)
	if err == nil {
		result, _ := collection.DeleteOne(ctx, bson.M{"_id": objID})
		if result.DeletedCount > 0 {
			return nil
		}
	}
	
	// Try node_id
	result, err := collection.DeleteOne(ctx, bson.M{"node_id": nodeID})
	if err != nil {
		return errors.New("删除节点失败")
	}
	
	if result.DeletedCount == 0 {
		return errors.New("节点不存在")
	}
	
	return nil
}

// Heartbeat updates node heartbeat
func (s *NodeService) Heartbeat(nodeID string, systemInfo models.NodeSystemInfo, currentTasks int) error {
	return s.UpdateNode(nodeID, map[string]interface{}{
		"last_heartbeat": time.Now(),
		"system_info":    systemInfo,
		"current_tasks":  currentTasks,
		"status":         models.NodeStatusOnline,
	})
}

// SetNodeStatus sets node status
func (s *NodeService) SetNodeStatus(nodeID string, status models.NodeStatus) error {
	return s.UpdateNode(nodeID, map[string]interface{}{
		"status": status,
	})
}

// GetAvailableNode gets an available node for task execution
func (s *NodeService) GetAvailableNode(nodeType string, capabilities []string) (*models.ScannerNode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	filter := bson.M{
		"status": models.NodeStatusOnline,
		"$expr": bson.M{
			"$lt": []string{"$current_tasks", "$max_tasks"},
		},
	}
	
	if nodeType != "" {
		filter["type"] = nodeType
	}
	
	if len(capabilities) > 0 {
		filter["capabilities"] = bson.M{"$all": capabilities}
	}
	
	// Find node with least current tasks
	opts := options.FindOne().SetSort(bson.D{{Key: "current_tasks", Value: 1}})
	
	var node models.ScannerNode
	err := collection.FindOne(ctx, filter, opts).Decode(&node)
	if err != nil {
		return nil, errors.New("没有可用的节点")
	}
	
	return &node, nil
}

// GetNodeStats returns node statistics
func (s *NodeService) GetNodeStats() (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	// Count by status
	pipeline := []bson.M{
		{"$group": bson.M{
			"_id":   "$status",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, errors.New("统计失败")
	}
	defer cursor.Close(ctx)
	
	stats := make(map[string]interface{})
	statusStats := make(map[string]int)
	
	var results []struct {
		ID    string `bson:"_id"`
		Count int    `bson:"count"`
	}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, errors.New("解析统计数据失败")
	}
	
	total := 0
	for _, r := range results {
		statusStats[r.ID] = r.Count
		total += r.Count
	}
	
	stats["by_status"] = statusStats
	stats["total"] = total
	
	return stats, nil
}

// CheckOfflineNodes checks and marks offline nodes
func (s *NodeService) CheckOfflineNodes(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionNodes)
	
	threshold := time.Now().Add(-timeout)
	
	_, err := collection.UpdateMany(ctx,
		bson.M{
			"status":         models.NodeStatusOnline,
			"last_heartbeat": bson.M{"$lt": threshold},
		},
		bson.M{
			"$set": bson.M{
				"status":     models.NodeStatusOffline,
				"updated_at": time.Now(),
			},
		},
	)
	
	return err
}
