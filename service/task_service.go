package service

import (
	"context"
	"errors"
	"log"
	"time"

	"moongazing/database"
	"moongazing/models"

	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type TaskService struct{}

func NewTaskService() *TaskService {
	return &TaskService{}
}

// CreateTask creates a new task
func (s *TaskService) CreateTask(task *models.Task) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionTasks)
	
	task.ID = primitive.NewObjectID()
	task.Status = models.TaskStatusPending
	task.Progress = 0
	task.CreatedAt = time.Now()
	task.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, task)
	if err != nil {
		return errors.New("创建任务失败")
	}
	
	// Add to Redis task queue
	s.enqueueTask(task)
	
	return nil
}

// GetTaskByID retrieves task by ID
func (s *TaskService) GetTaskByID(taskID string) (*models.Task, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, errors.New("无效的任务ID")
	}
	
	collection := database.GetCollection(models.CollectionTasks)
	
	var task models.Task
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&task)
	if err != nil {
		return nil, errors.New("任务不存在")
	}
	
	return &task, nil
}

// ListTasks lists tasks with filtering and pagination
func (s *TaskService) ListTasks(workspaceID string, taskType string, status string, page, pageSize int) ([]*models.Task, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionTasks)
	
	filter := bson.M{}
	
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	if taskType != "" {
		filter["type"] = taskType
	}
	
	if status != "" {
		filter["status"] = status
	}
	
	// Get total count
	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, errors.New("查询任务数量失败")
	}
	
	// Query with pagination
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询任务列表失败")
	}
	defer cursor.Close(ctx)
	
	var tasks []*models.Task
	if err = cursor.All(ctx, &tasks); err != nil {
		return nil, 0, errors.New("解析任务数据失败")
	}
	
	return tasks, total, nil
}

// UpdateTask updates a task
func (s *TaskService) UpdateTask(taskID string, updates map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return errors.New("无效的任务ID")
	}
	
	collection := database.GetCollection(models.CollectionTasks)
	
	updates["updated_at"] = time.Now()
	_, err = collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		return errors.New("更新任务失败")
	}
	
	return nil
}

// DeleteTask deletes a task
func (s *TaskService) DeleteTask(taskID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return errors.New("无效的任务ID")
	}
	
	// Check if task is running
	task, _ := s.GetTaskByID(taskID)
	if task != nil && task.Status == models.TaskStatusRunning {
		return errors.New("不能删除正在运行的任务")
	}
	
	collection := database.GetCollection(models.CollectionTasks)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除任务失败")
	}
	
	return nil
}

// StartTask starts a pending task
func (s *TaskService) StartTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}
	
	if task.Status != models.TaskStatusPending && task.Status != models.TaskStatusPaused {
		return errors.New("任务状态不允许启动")
	}
	
	err = s.UpdateTask(taskID, map[string]interface{}{
		"status":     models.TaskStatusRunning,
		"started_at": time.Now(),
	})
	if err != nil {
		return err
	}
	
	// 更新任务状态后入队执行
	task.Status = models.TaskStatusRunning
	s.enqueueTask(task)
	
	return nil
}

// PauseTask pauses a running task
func (s *TaskService) PauseTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}
	
	if task.Status != models.TaskStatusRunning {
		return errors.New("只能暂停正在运行的任务")
	}
	
	return s.UpdateTask(taskID, map[string]interface{}{
		"status": models.TaskStatusPaused,
	})
}

// ResumeTask resumes a paused task
func (s *TaskService) ResumeTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}
	
	if task.Status != models.TaskStatusPaused {
		return errors.New("只能恢复已暂停的任务")
	}
	
	err = s.UpdateTask(taskID, map[string]interface{}{
		"status": models.TaskStatusRunning,
	})
	if err != nil {
		return err
	}
	
	// Re-enqueue task to continue
	task.Status = models.TaskStatusRunning
	s.enqueueTask(task)
	
	return nil
}

// CancelTask cancels a task
func (s *TaskService) CancelTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}
	
	if task.Status == models.TaskStatusCompleted {
		return errors.New("已完成的任务不能取消")
	}
	
	return s.UpdateTask(taskID, map[string]interface{}{
		"status": models.TaskStatusCancelled,
	})
}

// RetryTask retries a failed or cancelled task
func (s *TaskService) RetryTask(taskID string) error {
	task, err := s.GetTaskByID(taskID)
	if err != nil {
		return err
	}
	
	if task.Status != models.TaskStatusFailed && task.Status != models.TaskStatusCancelled {
		return errors.New("只能重试失败或已取消的任务")
	}
	
	err = s.UpdateTask(taskID, map[string]interface{}{
		"status":      models.TaskStatusPending,
		"retry_count": task.RetryCount + 1,
		"last_error":  "",
	})
	if err != nil {
		return err
	}
	
	// Re-enqueue task
	task.Status = models.TaskStatusPending
	s.enqueueTask(task)
	
	return nil
}

// UpdateTaskProgress updates task progress
func (s *TaskService) UpdateTaskProgress(taskID string, progress int, stats models.TaskResultStats) error {
	updates := map[string]interface{}{
		"progress":     progress,
		"result_stats": stats,
	}
	
	if progress >= 100 {
		updates["status"] = models.TaskStatusCompleted
		updates["completed_at"] = time.Now()
	}
	
	return s.UpdateTask(taskID, updates)
}

// FailTask marks a task as failed
func (s *TaskService) FailTask(taskID string, errorMsg string) error {
	return s.UpdateTask(taskID, map[string]interface{}{
		"status":     models.TaskStatusFailed,
		"last_error": errorMsg,
	})
}

// GetTaskStats returns task statistics
func (s *TaskService) GetTaskStats(workspaceID string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionTasks)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["workspace_id"] = wsID
	}
	
	// Count by status
	pipeline := []bson.M{
		{"$match": filter},
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

// enqueueTask adds task to Redis queue
func (s *TaskService) enqueueTask(task *models.Task) {
	ctx := context.Background()
	rdb := database.GetRedis()
	
	// Add to task queue
	queueKey := "task:queue:" + string(task.Type)
	log.Printf("[TaskService] Enqueueing task %s to queue: %s", task.ID.Hex(), queueKey)
	rdb.RPush(ctx, queueKey, task.ID.Hex())
	
	// Set task status in Redis
	statusKey := "task:status:" + task.ID.Hex()
	rdb.Set(ctx, statusKey, string(task.Status), 24*time.Hour)
	log.Printf("[TaskService] Task %s enqueued successfully", task.ID.Hex())
}

// DequeueTask gets next task from queue
func (s *TaskService) DequeueTask(taskType string) (*models.Task, error) {
	ctx := context.Background()
	rdb := database.GetRedis()
	
	queueKey := "task:queue:" + taskType
	result, err := rdb.LPop(ctx, queueKey).Result()
	if err == redis.Nil {
		return nil, nil // No task in queue
	}
	if err != nil {
		return nil, err
	}
	
	return s.GetTaskByID(result)
}

// CreateTaskTemplate creates a task template
func (s *TaskService) CreateTaskTemplate(template *models.TaskTemplate) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionTaskTemplates)
	
	template.ID = primitive.NewObjectID()
	template.CreatedAt = time.Now()
	template.UpdatedAt = time.Now()
	
	_, err := collection.InsertOne(ctx, template)
	if err != nil {
		return errors.New("创建任务模板失败")
	}
	
	return nil
}

// ListTaskTemplates lists task templates
func (s *TaskService) ListTaskTemplates(workspaceID string, isPublic *bool) ([]*models.TaskTemplate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionTaskTemplates)
	
	filter := bson.M{}
	if workspaceID != "" {
		wsID, _ := primitive.ObjectIDFromHex(workspaceID)
		filter["$or"] = []bson.M{
			{"workspace_id": wsID},
			{"is_public": true},
		}
	}
	if isPublic != nil {
		filter["is_public"] = *isPublic
	}
	
	cursor, err := collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
	if err != nil {
		return nil, errors.New("查询任务模板失败")
	}
	defer cursor.Close(ctx)
	
	var templates []*models.TaskTemplate
	if err = cursor.All(ctx, &templates); err != nil {
		return nil, errors.New("解析任务模板数据失败")
	}
	
	return templates, nil
}

// GetTaskTemplate gets a task template by ID
func (s *TaskService) GetTaskTemplate(templateID string) (*models.TaskTemplate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(templateID)
	if err != nil {
		return nil, errors.New("无效的模板ID")
	}
	
	collection := database.GetCollection(models.CollectionTaskTemplates)
	
	var template models.TaskTemplate
	err = collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&template)
	if err != nil {
		return nil, errors.New("模板不存在")
	}
	
	return &template, nil
}

// DeleteTaskTemplate deletes a task template
func (s *TaskService) DeleteTaskTemplate(templateID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(templateID)
	if err != nil {
		return errors.New("无效的模板ID")
	}
	
	collection := database.GetCollection(models.CollectionTaskTemplates)
	
	_, err = collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return errors.New("删除模板失败")
	}
	
	return nil
}

// AddTaskLog adds a log entry for a task
func (s *TaskService) AddTaskLog(taskID string, level string, message string, detail string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return errors.New("无效的任务ID")
	}
	
	collection := database.GetCollection(models.CollectionTaskLogs)
	
	log := &models.TaskLog{
		ID:        primitive.NewObjectID(),
		TaskID:    objID,
		Level:     level,
		Message:   message,
		Detail:    detail,
		CreatedAt: time.Now(),
	}
	
	_, err = collection.InsertOne(ctx, log)
	if err != nil {
		return errors.New("添加日志失败")
	}
	
	return nil
}

// GetTaskLogs gets logs for a task
func (s *TaskService) GetTaskLogs(taskID string, page, pageSize int) ([]*models.TaskLog, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	objID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return nil, 0, errors.New("无效的任务ID")
	}
	
	collection := database.GetCollection(models.CollectionTaskLogs)
	
	filter := bson.M{"task_id": objID}
	
	total, _ := collection.CountDocuments(ctx, filter)
	
	opts := options.Find().
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize)).
		SetSort(bson.D{{Key: "created_at", Value: -1}})
	
	cursor, err := collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, errors.New("查询日志失败")
	}
	defer cursor.Close(ctx)
	
	var logs []*models.TaskLog
	if err = cursor.All(ctx, &logs); err != nil {
		return nil, 0, errors.New("解析日志数据失败")
	}
	
	return logs, total, nil
}
