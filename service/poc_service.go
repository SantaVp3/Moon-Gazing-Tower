package service

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"log"
	"os"
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

// ImportFromZip 从 ZIP 文件导入 POC（优化版：批量操作）
func (s *POCService) ImportFromZip(reader io.ReaderAt, size int64) (*ImportResult, error) {
	result := &ImportResult{
		Errors: make([]string, 0),
	}

	// 打开 ZIP 文件
	zipReader, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, errors.New("failed to read ZIP file: " + err.Error())
	}

	// 第一步：解析所有 YAML 文件，收集 POC 数据
	type parsedPOC struct {
		poc        *models.POC
		templateID string
		name       string
	}
	var parsedPOCs []parsedPOC
	templateIDs := make([]string, 0)
	names := make([]string, 0)

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

		// 解析标签
		var tags []string
		if template.Info.Tags != "" {
			tags = strings.Split(template.Info.Tags, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		}

		// 创建 POC 对象
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

		parsedPOCs = append(parsedPOCs, parsedPOC{
			poc:        poc,
			templateID: template.ID,
			name:       template.Info.Name,
		})
		templateIDs = append(templateIDs, template.ID)
		names = append(names, template.Info.Name)
	}

	if len(parsedPOCs) == 0 {
		return result, nil
	}

	// 第二步：批量查询已存在的 template_id 和 name
	collection := database.GetCollection("pocs")
	ctx := context.Background()

	existingTemplateIDs := make(map[string]bool)
	existingNames := make(map[string]bool)

	// 批量查询已存在的 template_id
	if len(templateIDs) > 0 {
		cursor, err := collection.Find(ctx, bson.M{
			"template_id": bson.M{"$in": templateIDs},
		}, options.Find().SetProjection(bson.M{"template_id": 1}))
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var doc struct {
					TemplateID string `bson:"template_id"`
				}
				if cursor.Decode(&doc) == nil {
					existingTemplateIDs[doc.TemplateID] = true
				}
			}
		}
	}

	// 批量查询已存在的 name
	if len(names) > 0 {
		cursor, err := collection.Find(ctx, bson.M{
			"name": bson.M{"$in": names},
		}, options.Find().SetProjection(bson.M{"name": 1}))
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var doc struct {
					Name string `bson:"name"`
				}
				if cursor.Decode(&doc) == nil {
					existingNames[doc.Name] = true
				}
			}
		}
	}

	// 第三步：筛选需要插入的 POC
	var toInsert []interface{}
	now := time.Now()

	for _, p := range parsedPOCs {
		// 检查是否已存在
		if existingTemplateIDs[p.templateID] || existingNames[p.name] {
			result.Skipped++
			continue
		}

		// 标记为已处理，避免同一批次内重复
		existingTemplateIDs[p.templateID] = true
		existingNames[p.name] = true

		// 设置 ID 和时间戳
		p.poc.ID = primitive.NewObjectID()
		p.poc.CreatedAt = now
		p.poc.UpdatedAt = now

		toInsert = append(toInsert, p.poc)
	}

	// 第四步：批量插入
	if len(toInsert) > 0 {
		// 分批插入，每批 500 个
		batchSize := 500
		for i := 0; i < len(toInsert); i += batchSize {
			end := i + batchSize
			if end > len(toInsert) {
				end = len(toInsert)
			}
			batch := toInsert[i:end]

			_, err := collection.InsertMany(ctx, batch)
			if err != nil {
				// 如果批量插入失败，尝试逐个插入
				for _, doc := range batch {
					_, insertErr := collection.InsertOne(ctx, doc)
					if insertErr != nil {
						result.Failed++
						if poc, ok := doc.(*models.POC); ok {
							result.Errors = append(result.Errors, "Failed to save "+poc.Name+": "+insertErr.Error())
						}
					} else {
						result.Imported++
					}
				}
			} else {
				result.Imported += len(batch)
			}
		}
	}

	return result, nil
}

// ImportFromDirectory 从目录导入 POC（支持递归扫描子目录）
func (s *POCService) ImportFromDirectory(dirPath string) (*ImportResult, error) {
	result := &ImportResult{
		Errors: make([]string, 0),
	}

	// 检查目录是否存在
	info, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		return result, nil // 目录不存在，直接返回空结果
	}
	if err != nil {
		return nil, errors.New("failed to access directory: " + err.Error())
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory: " + dirPath)
	}

	// 收集所有 YAML 文件
	type parsedPOC struct {
		poc        *models.POC
		templateID string
		name       string
	}
	var parsedPOCs []parsedPOC
	templateIDs := make([]string, 0)
	names := make([]string, 0)

	// 递归遍历目录
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 跳过无法访问的文件
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 只处理 YAML 文件
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// 跳过隐藏文件
		baseName := filepath.Base(path)
		if strings.HasPrefix(baseName, ".") {
			return nil
		}

		// 读取文件内容
		content, err := os.ReadFile(path)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to read "+path+": "+err.Error())
			return nil
		}

		// 解析 YAML
		var template NucleiTemplate
		if err := yaml.Unmarshal(content, &template); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to parse "+path+": "+err.Error())
			return nil
		}

		// 验证必要字段
		if template.ID == "" || template.Info.Name == "" {
			result.Failed++
			result.Errors = append(result.Errors, "Invalid template "+path+": missing id or name")
			return nil
		}

		// 解析标签
		var tags []string
		if template.Info.Tags != "" {
			tags = strings.Split(template.Info.Tags, ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
		}

		// 创建 POC 对象
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
			Source:      "directory",
		}

		parsedPOCs = append(parsedPOCs, parsedPOC{
			poc:        poc,
			templateID: template.ID,
			name:       template.Info.Name,
		})
		templateIDs = append(templateIDs, template.ID)
		names = append(names, template.Info.Name)

		return nil
	})

	if err != nil {
		return nil, errors.New("failed to walk directory: " + err.Error())
	}

	if len(parsedPOCs) == 0 {
		return result, nil
	}

	// 批量查询已存在的 template_id 和 name
	collection := database.GetCollection("pocs")
	ctx := context.Background()

	existingTemplateIDs := make(map[string]bool)
	existingNames := make(map[string]bool)

	// 批量查询已存在的 template_id
	if len(templateIDs) > 0 {
		cursor, err := collection.Find(ctx, bson.M{
			"template_id": bson.M{"$in": templateIDs},
		}, options.Find().SetProjection(bson.M{"template_id": 1}))
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var doc struct {
					TemplateID string `bson:"template_id"`
				}
				if cursor.Decode(&doc) == nil {
					existingTemplateIDs[doc.TemplateID] = true
				}
			}
		}
	}

	// 批量查询已存在的 name
	if len(names) > 0 {
		cursor, err := collection.Find(ctx, bson.M{
			"name": bson.M{"$in": names},
		}, options.Find().SetProjection(bson.M{"name": 1}))
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var doc struct {
					Name string `bson:"name"`
				}
				if cursor.Decode(&doc) == nil {
					existingNames[doc.Name] = true
				}
			}
		}
	}

	// 筛选需要插入的 POC
	var toInsert []interface{}
	now := time.Now()

	for _, p := range parsedPOCs {
		// 检查是否已存在
		if existingTemplateIDs[p.templateID] || existingNames[p.name] {
			result.Skipped++
			continue
		}

		// 标记为已处理，避免同一批次内重复
		existingTemplateIDs[p.templateID] = true
		existingNames[p.name] = true

		// 设置 ID 和时间戳
		p.poc.ID = primitive.NewObjectID()
		p.poc.CreatedAt = now
		p.poc.UpdatedAt = now

		toInsert = append(toInsert, p.poc)
	}

	// 批量插入
	if len(toInsert) > 0 {
		batchSize := 500
		for i := 0; i < len(toInsert); i += batchSize {
			end := i + batchSize
			if end > len(toInsert) {
				end = len(toInsert)
			}
			batch := toInsert[i:end]

			_, err := collection.InsertMany(ctx, batch)
			if err != nil {
				for _, doc := range batch {
					_, insertErr := collection.InsertOne(ctx, doc)
					if insertErr != nil {
						result.Failed++
						if poc, ok := doc.(*models.POC); ok {
							result.Errors = append(result.Errors, "Failed to save "+poc.Name+": "+insertErr.Error())
						}
					} else {
						result.Imported++
					}
				}
			} else {
				result.Imported += len(batch)
			}
		}
	}

	return result, nil
}

// ScanPOCDirectory 扫描 POC 目录并自动导入（启动时调用）
func (s *POCService) ScanPOCDirectory(pocDir string) {
	log.Printf("[POCService] Scanning POC directory: %s", pocDir)
	
	result, err := s.ImportFromDirectory(pocDir)
	if err != nil {
		log.Printf("[POCService] Failed to scan POC directory: %v", err)
		return
	}
	
	if result.Imported > 0 || result.Skipped > 0 || result.Failed > 0 {
		log.Printf("[POCService] POC directory scan complete: imported=%d, skipped=%d, failed=%d", 
			result.Imported, result.Skipped, result.Failed)
	} else {
		log.Printf("[POCService] No POC files found in directory: %s", pocDir)
	}
	
	if len(result.Errors) > 0 && len(result.Errors) <= 10 {
		for _, errMsg := range result.Errors {
			log.Printf("[POCService] Import error: %s", errMsg)
		}
	} else if len(result.Errors) > 10 {
		log.Printf("[POCService] %d import errors (showing first 10)", len(result.Errors))
		for i := 0; i < 10; i++ {
			log.Printf("[POCService] Import error: %s", result.Errors[i])
		}
	}
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
	collection := database.GetCollection("pocs")
	
	// 检查是否已存在（按 template_id 或 name 去重）
	var filter bson.M
	if poc.TemplateID != "" {
		filter = bson.M{"template_id": poc.TemplateID}
	} else if poc.Name != "" {
		filter = bson.M{"name": poc.Name}
	}
	
	if filter != nil {
		var existing models.POC
		err := collection.FindOne(context.Background(), filter).Decode(&existing)
		if err == nil {
			// 已存在，更新而不是插入
			poc.ID = existing.ID
			poc.CreatedAt = existing.CreatedAt
			poc.UpdatedAt = time.Now()
			_, err = collection.ReplaceOne(context.Background(), filter, poc)
			return err
		}
	}
	
	// 新建
	poc.ID = primitive.NewObjectID()
	poc.CreatedAt = time.Now()
	poc.UpdatedAt = time.Now()
	poc.Enabled = true
	
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

// BatchDelete 批量删除 POC
func (s *POCService) BatchDelete(ids []string) (int, int) {
	deleted := 0
	failed := 0
	
	collection := database.GetCollection("pocs")
	
	for _, id := range ids {
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			failed++
			continue
		}
		
		result, err := collection.DeleteOne(context.Background(), bson.M{"_id": objectID})
		if err != nil || result.DeletedCount == 0 {
			failed++
		} else {
			deleted++
		}
	}
	
	return deleted, failed
}

// ClearAll 清除所有 POC
func (s *POCService) ClearAll() (int64, error) {
	collection := database.GetCollection("pocs")
	result, err := collection.DeleteMany(context.Background(), bson.M{})
	if err != nil {
		return 0, err
	}
	return result.DeletedCount, nil
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
