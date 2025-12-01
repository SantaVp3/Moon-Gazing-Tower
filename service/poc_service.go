package service

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"moongazing/database"
	"moongazing/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/yaml.v3"
)

type POCService struct{}

func NewPOCService() *POCService {
	return &POCService{}
}

// ImportResult ZIP 导入结果
type ImportResult struct {
	Imported int      `json:"imported"`
	Failed   int      `json:"failed"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

// NucleiTemplate Nuclei 模板结构（用于解析）
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string   `yaml:"name"`
		Author      string   `yaml:"author"`
		Severity    string   `yaml:"severity"`
		Description string   `yaml:"description"`
		Reference   []string `yaml:"reference"`
		Tags        string   `yaml:"tags"`
		Classification struct {
			CVEID []string `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

// ImportFromZip 从 ZIP 文件导入 POC
func (s *POCService) ImportFromZip(reader io.ReaderAt, size int64) (*ImportResult, error) {
	result := &ImportResult{
		Errors: make([]string, 0),
	}

	// 打开 ZIP 文件
	zipReader, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, errors.New("failed to read ZIP file: " + err.Error())
	}

	// 遍历 ZIP 中的文件
	for _, file := range zipReader.File {
		// 跳过目录
		if file.FileInfo().IsDir() {
			continue
		}

		// 只处理 YAML 文件
		ext := strings.ToLower(filepath.Ext(file.Name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		// 跳过隐藏文件和 macOS 元数据
		baseName := filepath.Base(file.Name)
		if strings.HasPrefix(baseName, ".") || strings.HasPrefix(baseName, "__MACOSX") {
			continue
		}

		// 打开文件
		rc, err := file.Open()
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to open "+file.Name+": "+err.Error())
			continue
		}

		// 读取文件内容
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to read "+file.Name+": "+err.Error())
			continue
		}

		// 解析 YAML
		var template NucleiTemplate
		if err := yaml.Unmarshal(content, &template); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to parse "+file.Name+": "+err.Error())
			continue
		}

		// 验证必要字段
		if template.ID == "" || template.Info.Name == "" {
			result.Failed++
			result.Errors = append(result.Errors, "Invalid template "+file.Name+": missing id or name")
			continue
		}

		// 检查是否已存在（按 template ID 或名称去重）
		existingByID, _ := s.GetByTemplateID(template.ID)
		if existingByID != nil {
			result.Skipped++
			continue
		}
		existingByName, _ := s.GetByName(template.Info.Name)
		if existingByName != nil {
			result.Skipped++
			continue
		}

		// 解析标签
		var tags []string
		if template.Info.Tags != "" {
			tags = strings.Split(template.Info.Tags, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		}

		// 创建 POC
		poc := &models.POC{
			Name:        template.Info.Name,
			TemplateID:  template.ID,
			Description: template.Info.Description,
			Author:      template.Info.Author,
			Severity:    models.VulnSeverity(strings.ToLower(template.Info.Severity)),
			Type:        "nuclei",
			Tags:        tags,
			Content:     string(content),
			CVEID:       template.Info.Classification.CVEID,
			References:  template.Info.Reference,
			Enabled:     true,
			Version:     "1.0",
			Source:      "import",
		}

		if err := s.Create(poc); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to save "+file.Name+": "+err.Error())
			continue
		}

		result.Imported++
	}

	return result, nil
}

// GetByName 通过名称获取 POC
func (s *POCService) GetByName(name string) (*models.POC, error) {
	collection := database.GetCollection("pocs")
	var poc models.POC
	err := collection.FindOne(context.Background(), bson.M{"name": name}).Decode(&poc)
	if err != nil {
		return nil, err
	}
	return &poc, nil
}

// GetByTemplateID 通过 Nuclei 模板 ID 获取 POC
func (s *POCService) GetByTemplateID(templateID string) (*models.POC, error) {
	collection := database.GetCollection("pocs")
	var poc models.POC
	err := collection.FindOne(context.Background(), bson.M{"template_id": templateID}).Decode(&poc)
	if err != nil {
		return nil, err
	}
	return &poc, nil
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
