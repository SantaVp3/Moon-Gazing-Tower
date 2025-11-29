package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"moongazing/database"
	"moongazing/models"

	"github.com/robfig/cron/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CruiseService 巡航任务服务
type CruiseService struct {
	collection    *mongo.Collection
	logCollection *mongo.Collection
	scheduler     *cron.Cron
	taskService   *TaskService
	entryMap      map[string]cron.EntryID // cruiseID -> cronEntryID
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewCruiseService 创建巡航服务
func NewCruiseService() *CruiseService {
	ctx, cancel := context.WithCancel(context.Background())
	
	// 创建 cron 调度器，支持秒级（可选）
	scheduler := cron.New(cron.WithLocation(time.Local))
	
	service := &CruiseService{
		collection:    database.GetCollection("cruise_tasks"),
		logCollection: database.GetCollection("cruise_logs"),
		scheduler:     scheduler,
		taskService:   NewTaskService(),
		entryMap:      make(map[string]cron.EntryID),
		ctx:           ctx,
		cancel:        cancel,
	}
	
	return service
}

// Start 启动巡航调度器
func (s *CruiseService) Start() error {
	log.Println("[CruiseService] Starting cruise scheduler...")
	
	// 加载所有启用的巡航任务
	if err := s.loadEnabledCruises(); err != nil {
		log.Printf("[CruiseService] Failed to load cruises: %v", err)
		return err
	}
	
	// 启动调度器
	s.scheduler.Start()
	log.Println("[CruiseService] Cruise scheduler started")
	
	return nil
}

// Stop 停止巡航调度器
func (s *CruiseService) Stop() {
	log.Println("[CruiseService] Stopping cruise scheduler...")
	s.cancel()
	ctx := s.scheduler.Stop()
	<-ctx.Done()
	log.Println("[CruiseService] Cruise scheduler stopped")
}

// loadEnabledCruises 加载所有启用的巡航任务
func (s *CruiseService) loadEnabledCruises() error {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	
	filter := bson.M{"status": models.CruiseStatusEnabled}
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	
	var cruises []models.CruiseTask
	if err := cursor.All(ctx, &cruises); err != nil {
		return err
	}
	
	log.Printf("[CruiseService] Loading %d enabled cruise tasks", len(cruises))
	
	for _, cruise := range cruises {
		if err := s.scheduleCruise(&cruise); err != nil {
			log.Printf("[CruiseService] Failed to schedule cruise %s: %v", cruise.ID.Hex(), err)
		}
	}
	
	return nil
}

// scheduleCruise 调度单个巡航任务
func (s *CruiseService) scheduleCruise(cruise *models.CruiseTask) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// 如果已存在，先移除
	cruiseID := cruise.ID.Hex()
	if entryID, exists := s.entryMap[cruiseID]; exists {
		s.scheduler.Remove(entryID)
		delete(s.entryMap, cruiseID)
	}
	
	// 添加新的调度
	entryID, err := s.scheduler.AddFunc(cruise.CronExpr, func() {
		s.executeCruise(cruise.ID)
	})
	if err != nil {
		return fmt.Errorf("invalid cron expression: %v", err)
	}
	
	s.entryMap[cruiseID] = entryID
	
	// 更新下次执行时间
	entry := s.scheduler.Entry(entryID)
	s.updateNextRunTime(cruise.ID, entry.Next)
	
	log.Printf("[CruiseService] Scheduled cruise %s with cron: %s, next run: %v", 
		cruise.Name, cruise.CronExpr, entry.Next)
	
	return nil
}

// unscheduleCruise 取消调度
func (s *CruiseService) unscheduleCruise(cruiseID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if entryID, exists := s.entryMap[cruiseID]; exists {
		s.scheduler.Remove(entryID)
		delete(s.entryMap, cruiseID)
		log.Printf("[CruiseService] Unscheduled cruise %s", cruiseID)
	}
}

// executeCruise 执行巡航任务
func (s *CruiseService) executeCruise(cruiseID primitive.ObjectID) {
	log.Printf("[CruiseService] Executing cruise: %s", cruiseID.Hex())
	
	// 获取巡航任务
	cruise, err := s.GetCruise(cruiseID.Hex())
	if err != nil {
		log.Printf("[CruiseService] Failed to get cruise %s: %v", cruiseID.Hex(), err)
		return
	}
	
	// 检查状态
	if cruise.Status != models.CruiseStatusEnabled {
		log.Printf("[CruiseService] Cruise %s is not enabled, skipping", cruise.Name)
		return
	}
	
	// 更新状态为执行中
	s.updateCruiseStatus(cruiseID, models.CruiseStatusRunning)
	
	startTime := time.Now()
	
	// 创建扫描任务
	task := &models.Task{
		WorkspaceID: cruise.WorkspaceID,
		Name:        fmt.Sprintf("[巡航] %s - %s", cruise.Name, startTime.Format("2006-01-02 15:04")),
		Description: fmt.Sprintf("自动巡航任务，来源: %s", cruise.Name),
		Type:        cruise.TaskType,
		Status:      models.TaskStatusPending,
		Targets:     cruise.Targets,
		TargetType:  cruise.TargetType,
		Config:      cruise.Config,
		IsScheduled: true,
		CreatedBy:   cruise.CreatedBy,
		Tags:        append(cruise.Tags, "cruise", "auto"),
		CreatedAt:   startTime,
		UpdatedAt:   startTime,
	}
	
	// 保存任务 (CreateTask 返回 error)
	err = s.taskService.CreateTask(task)
	if err != nil {
		log.Printf("[CruiseService] Failed to create task for cruise %s: %v", cruise.Name, err)
		s.recordCruiseLog(cruiseID, primitive.NilObjectID, "failed", startTime, time.Now(), 0, 0, err.Error())
		s.updateCruiseStatus(cruiseID, models.CruiseStatusEnabled)
		s.incrementFailCount(cruiseID)
		return
	}
	
	taskID := task.ID.Hex()
	taskObjID := task.ID
	
	// 记录日志
	s.recordCruiseLog(cruiseID, taskObjID, "running", startTime, time.Time{}, 0, 0, "")
	
	// 更新巡航任务的最近执行信息
	s.updateLastRun(cruiseID, taskID, startTime)
	
	// 启动任务 - 任务已经通过 CreateTask 加入队列，会被 TaskExecutor workers 自动处理
	// 这里启动一个 goroutine 监控任务状态
	go func() {
		// 等待任务完成（轮询检查状态）
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		
		timeout := time.After(24 * time.Hour) // 最长等待24小时
		
		for {
			select {
			case <-ticker.C:
				// 获取任务状态
				updatedTask, err := s.taskService.GetTaskByID(taskID)
				if err != nil {
					log.Printf("[CruiseService] Failed to get task status: %v", err)
					continue
				}
				
				// 检查任务是否完成
				if updatedTask.Status == models.TaskStatusCompleted || 
				   updatedTask.Status == models.TaskStatusFailed ||
				   updatedTask.Status == models.TaskStatusCancelled {
					
					endTime := time.Now()
					duration := int64(endTime.Sub(startTime).Seconds())
					
					resultCount := updatedTask.ResultStats.DiscoveredAssets
					vulnCount := updatedTask.ResultStats.DiscoveredVulns
					status := "success"
					errorMsg := ""
					
					if updatedTask.Status == models.TaskStatusFailed {
						status = "failed"
						errorMsg = updatedTask.LastError
					} else if updatedTask.Status == models.TaskStatusCancelled {
						status = "cancelled"
					}
					
					// 更新日志
					s.updateCruiseLog(cruiseID, taskObjID, status, endTime, duration, resultCount, vulnCount, errorMsg)
					
					// 更新巡航状态
					s.updateCruiseStatus(cruiseID, models.CruiseStatusEnabled)
					s.updateLastStatus(cruiseID, status)
					
					if status == "success" {
						s.incrementSuccessCount(cruiseID)
					} else {
						s.incrementFailCount(cruiseID)
					}
					
					// 更新下次执行时间
					s.mu.RLock()
					if entryID, exists := s.entryMap[cruiseID.Hex()]; exists {
						entry := s.scheduler.Entry(entryID)
						s.updateNextRunTime(cruiseID, entry.Next)
					}
					s.mu.RUnlock()
					
					log.Printf("[CruiseService] Cruise %s completed, status: %s, results: %d, vulns: %d", 
						cruise.Name, status, resultCount, vulnCount)
					
					// TODO: 发送通知
					return
				}
				
			case <-timeout:
				log.Printf("[CruiseService] Cruise %s task timeout", cruise.Name)
				s.updateCruiseLog(cruiseID, taskObjID, "timeout", time.Now(), int64(24*time.Hour.Seconds()), 0, 0, "任务执行超时")
				s.updateCruiseStatus(cruiseID, models.CruiseStatusEnabled)
				s.incrementFailCount(cruiseID)
				return
			}
		}
	}()
}

// CreateCruise 创建巡航任务
func (s *CruiseService) CreateCruise(req *models.CruiseTaskCreateRequest, userID, workspaceID primitive.ObjectID) (*models.CruiseTask, error) {
	// 验证 Cron 表达式
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	_, err := parser.Parse(req.CronExpr)
	if err != nil {
		return nil, fmt.Errorf("invalid cron expression: %v", err)
	}
	
	now := time.Now()
	timezone := req.Timezone
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}
	
	cruise := &models.CruiseTask{
		ID:               primitive.NewObjectID(),
		WorkspaceID:      workspaceID,
		Name:             req.Name,
		Description:      req.Description,
		Status:           models.CruiseStatusDisabled, // 默认禁用，需手动启用
		CronExpr:         req.CronExpr,
		Timezone:         timezone,
		Targets:          req.Targets,
		TargetType:       req.TargetType,
		TaskType:         req.TaskType,
		Config:           req.Config,
		NotifyOnComplete: req.NotifyOnComplete,
		NotifyOnVuln:     req.NotifyOnVuln,
		NotifyChannels:   req.NotifyChannels,
		Tags:             req.Tags,
		CreatedBy:        userID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err = s.collection.InsertOne(ctx, cruise)
	if err != nil {
		return nil, err
	}

	log.Printf("[CruiseService] Created cruise task: %s (ID: %s, WorkspaceID: %s)", cruise.Name, cruise.ID.Hex(), cruise.WorkspaceID.Hex())
	return cruise, nil
}

// UpdateCruise 更新巡航任务
func (s *CruiseService) UpdateCruise(cruiseID string, req *models.CruiseTaskUpdateRequest) error {
	objID, err := primitive.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	
	update := bson.M{"updated_at": time.Now()}
	
	if req.Name != nil {
		update["name"] = *req.Name
	}
	if req.Description != nil {
		update["description"] = *req.Description
	}
	if req.CronExpr != nil {
		// 验证 Cron 表达式
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		if _, err := parser.Parse(*req.CronExpr); err != nil {
			return fmt.Errorf("invalid cron expression: %v", err)
		}
		update["cron_expr"] = *req.CronExpr
	}
	if req.Timezone != nil {
		update["timezone"] = *req.Timezone
	}
	if req.Targets != nil {
		update["targets"] = req.Targets
	}
	if req.TargetType != nil {
		update["target_type"] = *req.TargetType
	}
	if req.TaskType != nil {
		update["task_type"] = *req.TaskType
	}
	if req.Config != nil {
		update["config"] = *req.Config
	}
	if req.NotifyOnComplete != nil {
		update["notify_on_complete"] = *req.NotifyOnComplete
	}
	if req.NotifyOnVuln != nil {
		update["notify_on_vuln"] = *req.NotifyOnVuln
	}
	if req.NotifyChannels != nil {
		update["notify_channels"] = req.NotifyChannels
	}
	if req.Tags != nil {
		update["tags"] = req.Tags
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err = s.collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": update})
	if err != nil {
		return err
	}
	
	// 如果更新了 cron 表达式且任务已启用，重新调度
	if req.CronExpr != nil {
		cruise, _ := s.GetCruise(cruiseID)
		if cruise != nil && cruise.Status == models.CruiseStatusEnabled {
			s.scheduleCruise(cruise)
		}
	}
	
	return nil
}

// DeleteCruise 删除巡航任务
func (s *CruiseService) DeleteCruise(cruiseID string) error {
	objID, err := primitive.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	
	// 取消调度
	s.unscheduleCruise(cruiseID)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err = s.collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return err
	}
	
	// 删除相关日志
	s.logCollection.DeleteMany(ctx, bson.M{"cruise_id": objID})
	
	log.Printf("[CruiseService] Deleted cruise task: %s", cruiseID)
	return nil
}

// GetCruise 获取单个巡航任务
func (s *CruiseService) GetCruise(cruiseID string) (*models.CruiseTask, error) {
	objID, err := primitive.ObjectIDFromHex(cruiseID)
	if err != nil {
		return nil, err
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var cruise models.CruiseTask
	err = s.collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&cruise)
	if err != nil {
		return nil, err
	}
	
	return &cruise, nil
}

// ListCruises 列出巡航任务
func (s *CruiseService) ListCruises(workspaceID primitive.ObjectID, page, pageSize int, search string) ([]models.CruiseTask, int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{}
	if !workspaceID.IsZero() {
		filter["workspace_id"] = workspaceID
		log.Printf("[CruiseService] ListCruises with workspaceID: %s", workspaceID.Hex())
	} else {
		log.Printf("[CruiseService] ListCruises without workspaceID filter")
	}
	if search != "" {
		filter["$or"] = []bson.M{
			{"name": bson.M{"$regex": search, "$options": "i"}},
			{"description": bson.M{"$regex": search, "$options": "i"}},
		}
	}
	
	// 统计总数
	total, err := s.collection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	
	// 分页查询
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize))
	
	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)
	
	var cruises []models.CruiseTask
	if err := cursor.All(ctx, &cruises); err != nil {
		return nil, 0, err
	}

	// 确保返回空数组而不是 nil
	if cruises == nil {
		cruises = []models.CruiseTask{}
	}

	log.Printf("[CruiseService] ListCruises found %d cruises (total: %d, page: %d, pageSize: %d)", len(cruises), total, page, pageSize)

	return cruises, total, nil
}

// EnableCruise 启用巡航任务
func (s *CruiseService) EnableCruise(cruiseID string) error {
	cruise, err := s.GetCruise(cruiseID)
	if err != nil {
		return err
	}
	
	if cruise.Status == models.CruiseStatusEnabled {
		return nil
	}
	
	// 调度任务
	if err := s.scheduleCruise(cruise); err != nil {
		return err
	}
	
	// 更新状态
	return s.updateCruiseStatus(cruise.ID, models.CruiseStatusEnabled)
}

// DisableCruise 禁用巡航任务
func (s *CruiseService) DisableCruise(cruiseID string) error {
	objID, err := primitive.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	
	// 取消调度
	s.unscheduleCruise(cruiseID)
	
	// 更新状态
	return s.updateCruiseStatus(objID, models.CruiseStatusDisabled)
}

// RunNow 立即执行一次
func (s *CruiseService) RunNow(cruiseID string) error {
	objID, err := primitive.ObjectIDFromHex(cruiseID)
	if err != nil {
		return err
	}
	
	// 异步执行
	go s.executeCruise(objID)
	
	return nil
}

// GetCruiseLogs 获取巡航执行日志
func (s *CruiseService) GetCruiseLogs(cruiseID string, page, pageSize int) ([]models.CruiseLog, int64, error) {
	objID, err := primitive.ObjectIDFromHex(cruiseID)
	if err != nil {
		return nil, 0, err
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	filter := bson.M{"cruise_id": objID}
	
	total, err := s.logCollection.CountDocuments(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize))
	
	cursor, err := s.logCollection.Find(ctx, filter, opts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(ctx)
	
	var logs []models.CruiseLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, 0, err
	}

	// 确保返回空数组而不是 nil
	if logs == nil {
		logs = []models.CruiseLog{}
	}

	return logs, total, nil
}

// 辅助方法

func (s *CruiseService) updateCruiseStatus(cruiseID primitive.ObjectID, status models.CruiseStatus) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	_, err := s.collection.UpdateOne(ctx, 
		bson.M{"_id": cruiseID}, 
		bson.M{"$set": bson.M{"status": status, "updated_at": time.Now()}})
	return err
}

func (s *CruiseService) updateNextRunTime(cruiseID primitive.ObjectID, nextRun time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	s.collection.UpdateOne(ctx,
		bson.M{"_id": cruiseID},
		bson.M{"$set": bson.M{"next_run_at": nextRun}})
}

func (s *CruiseService) updateLastRun(cruiseID primitive.ObjectID, taskID string, lastRun time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	s.collection.UpdateOne(ctx,
		bson.M{"_id": cruiseID},
		bson.M{"$set": bson.M{
			"last_run_at": lastRun,
			"last_task_id": taskID,
		}, "$inc": bson.M{"run_count": 1}})
}

func (s *CruiseService) updateLastStatus(cruiseID primitive.ObjectID, status string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	s.collection.UpdateOne(ctx,
		bson.M{"_id": cruiseID},
		bson.M{"$set": bson.M{"last_status": status}})
}

func (s *CruiseService) incrementSuccessCount(cruiseID primitive.ObjectID) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	s.collection.UpdateOne(ctx,
		bson.M{"_id": cruiseID},
		bson.M{"$inc": bson.M{"success_count": 1}})
}

func (s *CruiseService) incrementFailCount(cruiseID primitive.ObjectID) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	s.collection.UpdateOne(ctx,
		bson.M{"_id": cruiseID},
		bson.M{"$inc": bson.M{"fail_count": 1}})
}

func (s *CruiseService) recordCruiseLog(cruiseID, taskID primitive.ObjectID, status string, startTime, endTime time.Time, resultCount, vulnCount int, errMsg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	duration := int64(0)
	if !endTime.IsZero() {
		duration = int64(endTime.Sub(startTime).Seconds())
	}
	
	log := models.CruiseLog{
		ID:          primitive.NewObjectID(),
		CruiseID:    cruiseID,
		TaskID:      taskID,
		Status:      status,
		StartTime:   startTime,
		EndTime:     endTime,
		Duration:    duration,
		ResultCount: resultCount,
		VulnCount:   vulnCount,
		Error:       errMsg,
		CreatedAt:   time.Now(),
	}
	
	s.logCollection.InsertOne(ctx, log)
}

func (s *CruiseService) updateCruiseLog(cruiseID, taskID primitive.ObjectID, status string, endTime time.Time, duration int64, resultCount, vulnCount int, errMsg string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	s.logCollection.UpdateOne(ctx,
		bson.M{"cruise_id": cruiseID, "task_id": taskID},
		bson.M{"$set": bson.M{
			"status":       status,
			"end_time":     endTime,
			"duration":     duration,
			"result_count": resultCount,
			"vuln_count":   vulnCount,
			"error":        errMsg,
		}})
}

// GetStats 获取巡航统计
func (s *CruiseService) GetStats(workspaceID primitive.ObjectID) map[string]interface{} {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	filter := bson.M{}
	if !workspaceID.IsZero() {
		filter["workspace_id"] = workspaceID
	}
	
	total, _ := s.collection.CountDocuments(ctx, filter)
	
	enabledFilter := bson.M{"status": models.CruiseStatusEnabled}
	if !workspaceID.IsZero() {
		enabledFilter["workspace_id"] = workspaceID
	}
	enabled, _ := s.collection.CountDocuments(ctx, enabledFilter)
	
	runningFilter := bson.M{"status": models.CruiseStatusRunning}
	if !workspaceID.IsZero() {
		runningFilter["workspace_id"] = workspaceID
	}
	running, _ := s.collection.CountDocuments(ctx, runningFilter)
	
	return map[string]interface{}{
		"total":    total,
		"enabled":  enabled,
		"disabled": total - enabled - running,
		"running":  running,
	}
}
