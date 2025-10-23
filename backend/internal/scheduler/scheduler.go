package scheduler

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
	"github.com/reconmaster/backend/internal/services"
	"github.com/robfig/cron/v3"
)

// Scheduler 调度器
type Scheduler struct {
	cron        *cron.Cron
	taskService *services.TaskService
}

// NewScheduler 创建调度器
func NewScheduler(taskService *services.TaskService) *Scheduler {
	return &Scheduler{
		cron:        cron.New(),
		taskService: taskService,
	}
}

// Start 启动调度器
func (s *Scheduler) Start() {
	log.Println("Scheduler started")

	// 启动监控任务检查
	s.cron.AddFunc("@every 1m", s.checkMonitorTasks)

	// 启动计划任务检查
	s.cron.AddFunc("@every 1m", s.checkScheduledTasks)

	s.cron.Start()
}

// Stop 停止调度器
func (s *Scheduler) Stop() {
	s.cron.Stop()
	log.Println("Scheduler stopped")
}

// checkMonitorTasks 检查并执行监控任务
func (s *Scheduler) checkMonitorTasks() {
	var monitors []models.Monitor

	// 查询活跃的监控任务
	database.DB.Where("status = ?", models.MonitorStatusActive).Find(&monitors)

	now := time.Now()

	for _, monitor := range monitors {
		// 检查是否需要执行
		if monitor.NextRunTime != nil && now.After(*monitor.NextRunTime) {
			log.Printf("Executing monitor task: %s (RunCount: %d)", monitor.Name, monitor.RunCount)

			// 更新运行信息
			monitor.LastRunTime = &now
			monitor.RunCount++
			nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
			monitor.NextRunTime = &nextRun
			monitor.LastError = "" // 清空上次错误
			database.DB.Save(&monitor)

			// 执行监控任务（异步）
			go s.executeMonitorWithErrorHandling(&monitor)
		} else if monitor.NextRunTime == nil {
			// 首次执行，设置下次运行时间
			nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
			monitor.NextRunTime = &nextRun
			database.DB.Save(&monitor)
		}
	}
}

// executeMonitorWithErrorHandling 执行监控任务（带错误处理）
func (s *Scheduler) executeMonitorWithErrorHandling(monitor *models.Monitor) {
	defer func() {
		if r := recover(); r != nil {
			errorMsg := fmt.Sprintf("Monitor task panic: %v", r)
			log.Printf("❌ %s", errorMsg)

			// 记录错误
			database.DB.Model(monitor).Update("last_error", errorMsg)
		}
	}()

	// 执行监控
	if err := s.executeMonitor(monitor); err != nil {
		log.Printf("❌ Monitor task failed: %s - %v", monitor.Name, err)

		// 记录错误到数据库
		database.DB.Model(monitor).Update("last_error", err.Error())
	}
}

// executeMonitor 执行监控任务
func (s *Scheduler) executeMonitor(monitor *models.Monitor) error {
	log.Printf("Monitor task executing: %s (type: %s)", monitor.Name, monitor.Type)

	// 根据监控类型执行不同的逻辑
	switch monitor.Type {
	case models.MonitorTypeDomain:
		return s.executeDomainMonitor(monitor)
	case models.MonitorTypeIP:
		return s.executeIPMonitor(monitor)
	case models.MonitorTypeSite:
		return s.executeSiteMonitor(monitor)
	case models.MonitorTypeGithub:
		return s.executeGithubMonitor(monitor)
	case models.MonitorTypeWIH:
		return s.executeWIHMonitor(monitor)
	default:
		return fmt.Errorf("unknown monitor type: %s", monitor.Type)
	}
}

// executeDomainMonitor 执行域名监控
func (s *Scheduler) executeDomainMonitor(monitor *models.Monitor) error {
	log.Printf("Domain monitor: %s", monitor.Target)

	// 查询当前域名解析
	ips, err := net.LookupHost(monitor.Target)
	if err != nil {
		log.Printf("Domain lookup failed: %v", err)
		return fmt.Errorf("domain lookup failed: %w", err)
	}

	// 查询上次的记录
	var lastResult models.MonitorResult
	database.DB.Where("monitor_id = ?", monitor.ID).
		Order("created_at DESC").
		First(&lastResult)

	currentIPs := strings.Join(ips, ",")

	// 对比变化
	if lastResult.Data != currentIPs && lastResult.Data != "" {
		// 发现变化
		result := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "modified",
			Description: fmt.Sprintf("域名 %s 的IP地址发生变化", monitor.Target),
			Data:        fmt.Sprintf("旧IP: %s, 新IP: %s", lastResult.Data, currentIPs),
		}
		database.DB.Create(result)
		log.Printf("Domain change detected: %s", monitor.Target)
	}

	// 保存当前状态
	result := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("域名 %s 检查完成", monitor.Target),
		Data:        currentIPs,
	}
	database.DB.Create(result)
	return nil
}

// executeIPMonitor 执行IP监控
func (s *Scheduler) executeIPMonitor(monitor *models.Monitor) error {
	log.Printf("IP monitor: %s", monitor.Target)

	// 扫描该IP的开放端口（使用快速扫描）
	commonPorts := []int{80, 443, 22, 21, 3306, 3389, 8080, 8443}
	var openPorts []int

	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", monitor.Target, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	// 查询上次的记录
	var lastResult models.MonitorResult
	database.DB.Where("monitor_id = ?", monitor.ID).
		Order("created_at DESC").
		First(&lastResult)

	currentPorts := fmt.Sprintf("%v", openPorts)

	// 对比变化
	if lastResult.Data != currentPorts && lastResult.Data != "" {
		result := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "modified",
			Description: fmt.Sprintf("IP %s 的开放端口发生变化", monitor.Target),
			Data:        fmt.Sprintf("旧端口: %s, 新端口: %s", lastResult.Data, currentPorts),
		}
		database.DB.Create(result)
		log.Printf("IP ports change detected: %s", monitor.Target)
	}

	// 保存当前状态
	result := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("IP %s 检查完成，开放端口: %v", monitor.Target, openPorts),
		Data:        currentPorts,
	}
	database.DB.Create(result)
	return nil
}

// executeSiteMonitor 执行站点监控
func (s *Scheduler) executeSiteMonitor(monitor *models.Monitor) error {
	log.Printf("Site monitor: %s", monitor.Target)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(monitor.Target)
	if err != nil {
		log.Printf("Site request failed: %v", err)
		return fmt.Errorf("site request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// 计算内容hash (简单实现)
	contentHash := fmt.Sprintf("%d", len(bodyStr))
	statusCode := resp.StatusCode

	// 查询上次的记录
	var lastResult models.MonitorResult
	database.DB.Where("monitor_id = ?", monitor.ID).
		Order("created_at DESC").
		First(&lastResult)

	currentData := fmt.Sprintf("status:%d,hash:%s", statusCode, contentHash)

	// 对比变化
	if lastResult.Data != currentData && lastResult.Data != "" {
		result := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "modified",
			Description: fmt.Sprintf("站点 %s 内容发生变化", monitor.Target),
			Data:        currentData,
		}
		database.DB.Create(result)
		log.Printf("Site change detected: %s", monitor.Target)
	}

	// 保存当前状态
	result := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("站点 %s 检查完成", monitor.Target),
		Data:        currentData,
	}
	database.DB.Create(result)
	return nil
}

// executeGithubMonitor 执行Github监控
func (s *Scheduler) executeGithubMonitor(monitor *models.Monitor) error {
	log.Printf("Github monitor: %s", monitor.Target)

	// 创建Github监控器
	githubMonitor := scanner.NewGithubMonitor("")

	// 搜索关键字
	result, err := githubMonitor.SearchKeyword(monitor.Target, 10)
	if err != nil {
		log.Printf("Github search failed: %v", err)
		return fmt.Errorf("github search failed: %w", err)
	}

	// 查询上次的记录
	var lastResult models.MonitorResult
	database.DB.Where("monitor_id = ?", monitor.ID).
		Order("created_at DESC").
		First(&lastResult)

	currentCount := fmt.Sprintf("%d", result.TotalCount)

	// 如果发现新结果
	if lastResult.Data != currentCount && result.TotalCount > 0 {
		monitorResult := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "new",
			Description: fmt.Sprintf("Github发现新的相关代码: %d 个结果", result.TotalCount),
			Data:        currentCount,
		}
		database.DB.Create(monitorResult)
		log.Printf("New Github results: %s (%d)", monitor.Target, result.TotalCount)
	}

	// 保存当前状态
	checkResult := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("Github监控完成: %s", monitor.Target),
		Data:        currentCount,
	}
	database.DB.Create(checkResult)
	return nil
}

// executeWIHMonitor 执行WIH监控
func (s *Scheduler) executeWIHMonitor(monitor *models.Monitor) error {
	log.Printf("WIH monitor: %s", monitor.Target)

	// 创建WIH扫描器
	wih := scanner.NewWebInfoHunter("")

	// 执行扫描
	ctx := &scanner.ScanContext{
		Logger: log.Default(),
		DB:     database.DB,
	}

	results, err := wih.Scan(ctx, []string{monitor.Target})
	if err != nil {
		log.Printf("WIH scan failed: %v", err)
		return fmt.Errorf("WIH scan failed: %w", err)
	}

	// 统计发现的信息
	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Subdomains) + len(r.AccessKeys) +
			len(r.SecretKeys) + len(r.APIKeys) + len(r.APIEndpoints)
	}

	// 查询上次的记录
	var lastResult models.MonitorResult
	database.DB.Where("monitor_id = ?", monitor.ID).
		Order("created_at DESC").
		First(&lastResult)

	currentData := fmt.Sprintf("%d", totalFindings)

	// 如果发现新信息
	if lastResult.Data != currentData && totalFindings > 0 {
		monitorResult := &models.MonitorResult{
			MonitorID:   monitor.ID,
			ChangeType:  "new",
			Description: fmt.Sprintf("WIH发现新的信息: %d 项", totalFindings),
			Data:        currentData,
		}
		database.DB.Create(monitorResult)
		log.Printf("New WIH findings: %s (%d)", monitor.Target, totalFindings)
	}

	// 保存当前状态
	checkResult := &models.MonitorResult{
		MonitorID:   monitor.ID,
		ChangeType:  "check",
		Description: fmt.Sprintf("WIH监控完成: %s", monitor.Target),
		Data:        currentData,
	}
	database.DB.Create(checkResult)
	return nil
}

// checkScheduledTasks 检查并执行计划任务
func (s *Scheduler) checkScheduledTasks() {
	var scheduledTasks []models.ScheduledTask

	// 查询已启用的计划任务
	database.DB.Where("is_enabled = ?", true).Find(&scheduledTasks)

	now := time.Now()

	for _, scheduledTask := range scheduledTasks {
		// 检查是否需要执行
		if scheduledTask.NextRunAt != nil && now.After(*scheduledTask.NextRunAt) {
			log.Printf("📅 Executing scheduled task: %s (Type: %s)", scheduledTask.Name, scheduledTask.CronType)

			// 执行计划任务（异步）
			go s.executeScheduledTask(&scheduledTask)
		}
	}
}

// executeScheduledTask 执行计划任务
func (s *Scheduler) executeScheduledTask(scheduledTask *models.ScheduledTask) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("❌ Scheduled task panic: %s - %v", scheduledTask.Name, r)

			// 增加失败计数
			scheduledTask.FailCount++
			database.DB.Save(scheduledTask)

			// 记录失败日志
			logEntry := &models.ScheduledTaskLog{
				ScheduledTaskID: scheduledTask.ID,
				Status:          "failed",
				Message:         fmt.Sprintf("Task panic: %v", r),
				StartTime:       time.Now(),
			}
			endTime := time.Now()
			logEntry.EndTime = &endTime
			database.DB.Create(logEntry)
		}
	}()

	startTime := time.Now()

	// 创建任务
	task := &models.Task{
		Name:     fmt.Sprintf("%s (计划任务)", scheduledTask.Name),
		Target:   scheduledTask.TaskOptions.Target,
		PolicyID: scheduledTask.PolicyID, // 使用计划任务关联的策略
		Status:   models.TaskStatusPending,
		Options:  scheduledTask.TaskOptions,
	}

	if err := database.DB.Create(task).Error; err != nil {
		log.Printf("❌ Failed to create task for scheduled task %s: %v", scheduledTask.Name, err)

		// 增加失败计数
		scheduledTask.FailCount++
		database.DB.Save(scheduledTask)

		// 记录失败日志
		logEntry := &models.ScheduledTaskLog{
			ScheduledTaskID: scheduledTask.ID,
			Status:          "failed",
			Message:         fmt.Sprintf("Failed to create task: %v", err),
			StartTime:       startTime,
		}
		endTime := time.Now()
		logEntry.EndTime = &endTime
		database.DB.Create(logEntry)
		return
	}

	log.Printf("✅ Task created for scheduled task %s: %s", scheduledTask.Name, task.ID)

	// 异步启动任务执行
	go s.taskService.ExecuteTask(task.ID)

	// 更新计划任务统计和下次运行时间
	scheduledTask.LastRunAt = &startTime
	scheduledTask.RunCount++

	// 计算下次运行时间
	if scheduledTask.CronType == "once" {
		// 一次性任务，执行后禁用
		scheduledTask.IsEnabled = false
		scheduledTask.NextRunAt = nil
		log.Printf("📅 One-time scheduled task completed, disabled: %s", scheduledTask.Name)
	} else {
		// 计算下次运行时间
		nextRun, err := s.calculateNextRun(scheduledTask.CronExpr, scheduledTask.CronType)
		if err != nil {
			log.Printf("⚠️ Failed to calculate next run for %s: %v", scheduledTask.Name, err)
		} else {
			scheduledTask.NextRunAt = nextRun
			log.Printf("📅 Next run scheduled for %s: %s", scheduledTask.Name, nextRun.Format("2006-01-02 15:04:05"))
		}
	}

	database.DB.Save(scheduledTask)

	// 记录成功日志
	logEntry := &models.ScheduledTaskLog{
		ScheduledTaskID: scheduledTask.ID,
		TaskID:          task.ID,
		Status:          "success",
		Message:         "Task created and started successfully",
		StartTime:       startTime,
	}
	endTime := time.Now()
	logEntry.EndTime = &endTime
	database.DB.Create(logEntry)
}

// calculateNextRun 计算下次运行时间
func (s *Scheduler) calculateNextRun(cronExpr, cronType string) (*time.Time, error) {
	if cronType == "once" {
		return nil, nil
	}

	if cronExpr == "" {
		return nil, fmt.Errorf("cron expression is empty")
	}

	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(cronExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cron expression: %w", err)
	}

	nextRun := schedule.Next(time.Now())
	return &nextRun, nil
}
