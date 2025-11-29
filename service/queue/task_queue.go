package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

// TaskQueue 分布式任务队列
type TaskQueue struct {
	client       *redis.Client
	workers      int
	handlers     map[string]TaskHandler
	handlersMu   sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
	
	// 队列配置
	queueKey     string
	processingKey string
	deadLetterKey string
	resultKey    string
	
	// 任务超时配置
	taskTimeout  time.Duration
	maxRetries   int
}

// Task 任务定义
type Task struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Payload     map[string]interface{} `json:"payload"`
	Priority    int                    `json:"priority"`
	CreatedAt   time.Time              `json:"created_at"`
	ScheduledAt time.Time              `json:"scheduled_at,omitempty"`
	StartedAt   time.Time              `json:"started_at,omitempty"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	Retries     int                    `json:"retries"`
	MaxRetries  int                    `json:"max_retries"`
	Status      TaskStatus             `json:"status"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	WorkerID    string                 `json:"worker_id,omitempty"`
}

// TaskStatus 任务状态
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusScheduled  TaskStatus = "scheduled"
	TaskStatusProcessing TaskStatus = "processing"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusRetrying   TaskStatus = "retrying"
)

// TaskHandler 任务处理器
type TaskHandler func(ctx context.Context, task *Task) (interface{}, error)

// TaskResult 任务结果
type TaskResult struct {
	TaskID      string      `json:"task_id"`
	Status      TaskStatus  `json:"status"`
	Result      interface{} `json:"result,omitempty"`
	Error       string      `json:"error,omitempty"`
	CompletedAt time.Time   `json:"completed_at"`
}

// QueueConfig 队列配置
type QueueConfig struct {
	RedisAddr    string
	RedisPassword string
	RedisDB      int
	QueueName    string
	Workers      int
	TaskTimeout  time.Duration
	MaxRetries   int
}

// DefaultQueueConfig 默认配置
func DefaultQueueConfig() *QueueConfig {
	return &QueueConfig{
		RedisAddr:   "localhost:6379",
		RedisPassword: "",
		RedisDB:     0,
		QueueName:   "moon-gazing-tower",
		Workers:     10,
		TaskTimeout: 30 * time.Minute,
		MaxRetries:  3,
	}
}

// NewTaskQueue 创建任务队列
func NewTaskQueue(config *QueueConfig) (*TaskQueue, error) {
	if config == nil {
		config = DefaultQueueConfig()
	}
	
	client := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})
	
	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}
	
	return &TaskQueue{
		client:        client,
		workers:       config.Workers,
		handlers:      make(map[string]TaskHandler),
		stopCh:        make(chan struct{}),
		queueKey:      config.QueueName + ":queue",
		processingKey: config.QueueName + ":processing",
		deadLetterKey: config.QueueName + ":deadletter",
		resultKey:     config.QueueName + ":result:",
		taskTimeout:   config.TaskTimeout,
		maxRetries:    config.MaxRetries,
	}, nil
}

// RegisterHandler 注册任务处理器
func (q *TaskQueue) RegisterHandler(taskType string, handler TaskHandler) {
	q.handlersMu.Lock()
	defer q.handlersMu.Unlock()
	q.handlers[taskType] = handler
}

// Start 启动工作者
func (q *TaskQueue) Start() {
	for i := 0; i < q.workers; i++ {
		q.wg.Add(1)
		go q.worker(fmt.Sprintf("worker-%d", i))
	}
	
	// 启动超时任务检查
	q.wg.Add(1)
	go q.timeoutChecker()
	
	log.Printf("[TaskQueue] Started %d workers", q.workers)
}

// Stop 停止队列
func (q *TaskQueue) Stop() {
	close(q.stopCh)
	q.wg.Wait()
	q.client.Close()
	log.Println("[TaskQueue] Stopped")
}

// Enqueue 添加任务到队列
func (q *TaskQueue) Enqueue(ctx context.Context, taskType string, payload map[string]interface{}) (*Task, error) {
	task := &Task{
		ID:         uuid.New().String(),
		Type:       taskType,
		Payload:    payload,
		Priority:   0,
		CreatedAt:  time.Now(),
		Status:     TaskStatusPending,
		MaxRetries: q.maxRetries,
	}
	
	return q.enqueueTask(ctx, task)
}

// EnqueueWithPriority 添加带优先级的任务
func (q *TaskQueue) EnqueueWithPriority(ctx context.Context, taskType string, payload map[string]interface{}, priority int) (*Task, error) {
	task := &Task{
		ID:         uuid.New().String(),
		Type:       taskType,
		Payload:    payload,
		Priority:   priority,
		CreatedAt:  time.Now(),
		Status:     TaskStatusPending,
		MaxRetries: q.maxRetries,
	}
	
	return q.enqueueTask(ctx, task)
}

// Schedule 调度延迟任务
func (q *TaskQueue) Schedule(ctx context.Context, taskType string, payload map[string]interface{}, delay time.Duration) (*Task, error) {
	task := &Task{
		ID:          uuid.New().String(),
		Type:        taskType,
		Payload:     payload,
		Priority:    0,
		CreatedAt:   time.Now(),
		ScheduledAt: time.Now().Add(delay),
		Status:      TaskStatusScheduled,
		MaxRetries:  q.maxRetries,
	}
	
	return q.scheduleTask(ctx, task)
}

// enqueueTask 内部入队方法
func (q *TaskQueue) enqueueTask(ctx context.Context, task *Task) (*Task, error) {
	data, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	
	// 使用 ZADD 实现优先级队列，score = -priority (负数使高优先级排前面)
	score := float64(-task.Priority)
	err = q.client.ZAdd(ctx, q.queueKey, &redis.Z{
		Score:  score,
		Member: string(data),
	}).Err()
	
	if err != nil {
		return nil, err
	}
	
	return task, nil
}

// scheduleTask 调度延迟任务
func (q *TaskQueue) scheduleTask(ctx context.Context, task *Task) (*Task, error) {
	data, err := json.Marshal(task)
	if err != nil {
		return nil, err
	}
	
	// 使用时间戳作为 score
	score := float64(task.ScheduledAt.Unix())
	err = q.client.ZAdd(ctx, q.queueKey+":scheduled", &redis.Z{
		Score:  score,
		Member: string(data),
	}).Err()
	
	if err != nil {
		return nil, err
	}
	
	return task, nil
}

// worker 工作者循环
func (q *TaskQueue) worker(workerID string) {
	defer q.wg.Done()
	
	for {
		select {
		case <-q.stopCh:
			return
		default:
		}
		
		// 首先处理到期的调度任务
		q.processScheduledTasks()
		
		// 从队列获取任务
		task, err := q.dequeue()
		if err != nil {
			if err != redis.Nil {
				log.Printf("[Worker %s] Dequeue error: %v", workerID, err)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		// 处理任务
		q.processTask(workerID, task)
	}
}

// dequeue 从队列获取任务
func (q *TaskQueue) dequeue() (*Task, error) {
	ctx := context.Background()
	
	// 使用 ZPOPMIN 获取最高优先级的任务
	results, err := q.client.ZPopMin(ctx, q.queueKey, 1).Result()
	if err != nil {
		return nil, err
	}
	
	if len(results) == 0 {
		return nil, redis.Nil
	}
	
	var task Task
	if err := json.Unmarshal([]byte(results[0].Member.(string)), &task); err != nil {
		return nil, err
	}
	
	// 添加到处理中集合
	task.Status = TaskStatusProcessing
	task.StartedAt = time.Now()
	
	data, _ := json.Marshal(task)
	q.client.HSet(ctx, q.processingKey, task.ID, string(data))
	
	return &task, nil
}

// processTask 处理任务
func (q *TaskQueue) processTask(workerID string, task *Task) {
	q.handlersMu.RLock()
	handler, ok := q.handlers[task.Type]
	q.handlersMu.RUnlock()
	
	if !ok {
		log.Printf("[Worker %s] No handler for task type: %s", workerID, task.Type)
		q.failTask(task, fmt.Errorf("no handler for task type: %s", task.Type))
		return
	}
	
	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), q.taskTimeout)
	defer cancel()
	
	task.WorkerID = workerID
	
	// 执行任务
	result, err := handler(ctx, task)
	
	if err != nil {
		q.handleTaskError(task, err)
		return
	}
	
	q.completeTask(task, result)
}

// handleTaskError 处理任务错误
func (q *TaskQueue) handleTaskError(task *Task, err error) {
	task.Retries++
	task.Error = err.Error()
	
	if task.Retries >= task.MaxRetries {
		q.failTask(task, err)
		return
	}
	
	// 重试
	task.Status = TaskStatusRetrying
	log.Printf("[TaskQueue] Task %s retry %d/%d: %v", task.ID, task.Retries, task.MaxRetries, err)
	
	// 延迟重试 (指数退避)
	delay := time.Duration(task.Retries*task.Retries) * time.Second
	task.ScheduledAt = time.Now().Add(delay)
	
	ctx := context.Background()
	q.client.HDel(ctx, q.processingKey, task.ID)
	q.scheduleTask(ctx, task)
}

// failTask 任务失败
func (q *TaskQueue) failTask(task *Task, err error) {
	task.Status = TaskStatusFailed
	task.CompletedAt = time.Now()
	task.Error = err.Error()
	
	ctx := context.Background()
	
	// 从处理中移除
	q.client.HDel(ctx, q.processingKey, task.ID)
	
	// 添加到死信队列
	data, _ := json.Marshal(task)
	q.client.RPush(ctx, q.deadLetterKey, string(data))
	
	// 保存结果
	q.saveResult(task)
	
	log.Printf("[TaskQueue] Task %s failed: %v", task.ID, err)
}

// completeTask 任务完成
func (q *TaskQueue) completeTask(task *Task, result interface{}) {
	task.Status = TaskStatusCompleted
	task.CompletedAt = time.Now()
	task.Result = result
	
	ctx := context.Background()
	
	// 从处理中移除
	q.client.HDel(ctx, q.processingKey, task.ID)
	
	// 保存结果
	q.saveResult(task)
	
	log.Printf("[TaskQueue] Task %s completed", task.ID)
}

// saveResult 保存任务结果
func (q *TaskQueue) saveResult(task *Task) {
	ctx := context.Background()
	
	result := &TaskResult{
		TaskID:      task.ID,
		Status:      task.Status,
		Result:      task.Result,
		Error:       task.Error,
		CompletedAt: task.CompletedAt,
	}
	
	data, _ := json.Marshal(result)
	q.client.Set(ctx, q.resultKey+task.ID, string(data), 24*time.Hour)
}

// GetResult 获取任务结果
func (q *TaskQueue) GetResult(ctx context.Context, taskID string) (*TaskResult, error) {
	data, err := q.client.Get(ctx, q.resultKey+taskID).Result()
	if err != nil {
		return nil, err
	}
	
	var result TaskResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	
	return &result, nil
}

// processScheduledTasks 处理到期的调度任务
func (q *TaskQueue) processScheduledTasks() {
	ctx := context.Background()
	now := float64(time.Now().Unix())
	
	// 获取所有到期的任务
	results, err := q.client.ZRangeByScore(ctx, q.queueKey+":scheduled", &redis.ZRangeBy{
		Min: "-inf",
		Max: fmt.Sprintf("%f", now),
	}).Result()
	
	if err != nil || len(results) == 0 {
		return
	}
	
	for _, item := range results {
		var task Task
		if err := json.Unmarshal([]byte(item), &task); err != nil {
			continue
		}
		
		// 从调度队列移除
		q.client.ZRem(ctx, q.queueKey+":scheduled", item)
		
		// 添加到主队列
		task.Status = TaskStatusPending
		q.enqueueTask(ctx, &task)
	}
}

// timeoutChecker 超时检查器
func (q *TaskQueue) timeoutChecker() {
	defer q.wg.Done()
	
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			q.checkTimeouts()
		}
	}
}

// checkTimeouts 检查超时任务
func (q *TaskQueue) checkTimeouts() {
	ctx := context.Background()
	
	// 获取所有处理中的任务
	tasks, err := q.client.HGetAll(ctx, q.processingKey).Result()
	if err != nil {
		return
	}
	
	for taskID, data := range tasks {
		var task Task
		if err := json.Unmarshal([]byte(data), &task); err != nil {
			continue
		}
		
		// 检查是否超时
		if time.Since(task.StartedAt) > q.taskTimeout {
			log.Printf("[TaskQueue] Task %s timed out", taskID)
			q.handleTaskError(&task, fmt.Errorf("task timeout after %v", q.taskTimeout))
		}
	}
}

// GetStats 获取队列统计
func (q *TaskQueue) GetStats(ctx context.Context) (map[string]interface{}, error) {
	pending, _ := q.client.ZCard(ctx, q.queueKey).Result()
	scheduled, _ := q.client.ZCard(ctx, q.queueKey+":scheduled").Result()
	processing, _ := q.client.HLen(ctx, q.processingKey).Result()
	deadLetter, _ := q.client.LLen(ctx, q.deadLetterKey).Result()
	
	return map[string]interface{}{
		"pending":     pending,
		"scheduled":   scheduled,
		"processing":  processing,
		"dead_letter": deadLetter,
		"workers":     q.workers,
	}, nil
}

// GetPendingTasks 获取待处理任务
func (q *TaskQueue) GetPendingTasks(ctx context.Context, limit int64) ([]*Task, error) {
	results, err := q.client.ZRange(ctx, q.queueKey, 0, limit-1).Result()
	if err != nil {
		return nil, err
	}
	
	tasks := make([]*Task, 0, len(results))
	for _, data := range results {
		var task Task
		if err := json.Unmarshal([]byte(data), &task); err != nil {
			continue
		}
		tasks = append(tasks, &task)
	}
	
	return tasks, nil
}

// GetProcessingTasks 获取处理中的任务
func (q *TaskQueue) GetProcessingTasks(ctx context.Context) ([]*Task, error) {
	results, err := q.client.HGetAll(ctx, q.processingKey).Result()
	if err != nil {
		return nil, err
	}
	
	tasks := make([]*Task, 0, len(results))
	for _, data := range results {
		var task Task
		if err := json.Unmarshal([]byte(data), &task); err != nil {
			continue
		}
		tasks = append(tasks, &task)
	}
	
	return tasks, nil
}

// GetDeadLetterTasks 获取死信队列任务
func (q *TaskQueue) GetDeadLetterTasks(ctx context.Context, limit int64) ([]*Task, error) {
	results, err := q.client.LRange(ctx, q.deadLetterKey, 0, limit-1).Result()
	if err != nil {
		return nil, err
	}
	
	tasks := make([]*Task, 0, len(results))
	for _, data := range results {
		var task Task
		if err := json.Unmarshal([]byte(data), &task); err != nil {
			continue
		}
		tasks = append(tasks, &task)
	}
	
	return tasks, nil
}

// RetryDeadLetter 重试死信队列任务
func (q *TaskQueue) RetryDeadLetter(ctx context.Context, taskID string) error {
	// 获取所有死信任务
	tasks, err := q.GetDeadLetterTasks(ctx, 1000)
	if err != nil {
		return err
	}
	
	for _, task := range tasks {
		if task.ID == taskID {
			// 重置任务状态
			task.Status = TaskStatusPending
			task.Retries = 0
			task.Error = ""
			task.Result = nil
			
			// 重新入队
			_, err := q.enqueueTask(ctx, task)
			if err != nil {
				return err
			}
			
			// 从死信队列移除 (简化处理)
			return nil
		}
	}
	
	return fmt.Errorf("task not found in dead letter queue")
}

// ClearDeadLetter 清空死信队列
func (q *TaskQueue) ClearDeadLetter(ctx context.Context) error {
	return q.client.Del(ctx, q.deadLetterKey).Err()
}

// GetWorkerStatus 获取Worker状态
func (q *TaskQueue) GetWorkerStatus(ctx context.Context) (map[string]interface{}, error) {
	processing, _ := q.client.HLen(ctx, q.processingKey).Result()

	return map[string]interface{}{
		"active":  int(processing),
		"total":   q.workers,
		"workers": []map[string]interface{}{}, // 简化实现，暂不返回详细worker信息
	}, nil
}
