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

type POCService struct{}

func NewPOCService() *POCService {
	return &POCService{}
}

func (s *POCService) Create(poc *models.POC) error {
	poc.ID = primitive.NewObjectID()
	poc.CreatedAt = time.Now()
	poc.UpdatedAt = time.Now()
	poc.Enabled = true
	
	collection := database.GetCollection("pocs")
	_, err := collection.InsertOne(context.Background(), poc)
	return err
}

func (s *POCService) GetByID(id string) (*models.POC, error) {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, errors.New("invalid poc id")
	}
	
	collection := database.GetCollection("pocs")
	var poc models.POC
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&poc)
	if err != nil {
		return nil, err
	}
	return &poc, nil
}

func (s *POCService) Update(id string, update bson.M) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return errors.New("invalid poc id")
	}
	
	update["updated_at"] = time.Now()
	
	collection := database.GetCollection("pocs")
	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID},
		bson.M{"$set": update},
	)
	return err
}

func (s *POCService) Delete(id string) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return errors.New("invalid poc id")
	}
	
	collection := database.GetCollection("pocs")
	_, err = collection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	return err
}

type POCListParams struct {
	Page     int64
	PageSize int64
	Type     string
	Severity string
	Enabled  *bool
	Search   string
}

type POCListResult struct {
	POCs  []models.POC `json:"pocs"`
	Total int64        `json:"total"`
}

func (s *POCService) List(params POCListParams) (*POCListResult, error) {
	collection := database.GetCollection("pocs")
	
	filter := bson.M{}
	if params.Type != "" {
		filter["type"] = params.Type
	}
	if params.Severity != "" {
		filter["severity"] = params.Severity
	}
	if params.Enabled != nil {
		filter["enabled"] = *params.Enabled
	}
	if params.Search != "" {
		filter["$or"] = []bson.M{
			{"name": bson.M{"$regex": params.Search, "$options": "i"}},
			{"description": bson.M{"$regex": params.Search, "$options": "i"}},
			{"cve_id": bson.M{"$regex": params.Search, "$options": "i"}},
		}
	}
	
	total, err := collection.CountDocuments(context.Background(), filter)
	if err != nil {
		return nil, err
	}
	
	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetSkip((params.Page - 1) * params.PageSize).
		SetLimit(params.PageSize)
	
	cursor, err := collection.Find(context.Background(), filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())
	
	var pocs []models.POC
	if err := cursor.All(context.Background(), &pocs); err != nil {
		return nil, err
	}
	
	if pocs == nil {
		pocs = []models.POC{}
	}
	
	return &POCListResult{
		POCs:  pocs,
		Total: total,
	}, nil
}

func (s *POCService) ToggleEnabled(id string, enabled bool) error {
	return s.Update(id, bson.M{"enabled": enabled})
}

func (s *POCService) GetStatistics() (map[string]interface{}, error) {
	collection := database.GetCollection("pocs")
	
	// Total count
	total, _ := collection.CountDocuments(context.Background(), bson.M{})
	
	// Enabled count
	enabledCount, _ := collection.CountDocuments(context.Background(), bson.M{"enabled": true})
	
	// By severity
	severityCounts := map[string]int64{}
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		count, _ := collection.CountDocuments(context.Background(), bson.M{"severity": severity})
		severityCounts[severity] = count
	}
	
	// By type
	typeCounts := map[string]int64{}
	for _, pocType := range []string{"nuclei", "xray", "custom"} {
		count, _ := collection.CountDocuments(context.Background(), bson.M{"type": pocType})
		typeCounts[pocType] = count
	}
	
	return map[string]interface{}{
		"total":    total,
		"enabled":  enabledCount,
		"disabled": total - enabledCount,
		"by_severity": severityCounts,
		"by_type":     typeCounts,
	}, nil
}
