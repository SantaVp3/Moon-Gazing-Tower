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
			log.Printf("Executing monitor task: %s", monitor.Name)
			
			// 更新上次运行时间
			monitor.LastRunTime = &now
			nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
			monitor.NextRunTime = &nextRun
			database.DB.Save(&monitor)
			
			// 执行监控任务（异步）
			go s.executeMonitor(&monitor)
		} else if monitor.NextRunTime == nil {
			// 首次执行，设置下次运行时间
			nextRun := now.Add(time.Duration(monitor.Interval) * time.Second)
			monitor.NextRunTime = &nextRun
			database.DB.Save(&monitor)
		}
	}
}

// executeMonitor 执行监控任务
func (s *Scheduler) executeMonitor(monitor *models.Monitor) {
	log.Printf("Monitor task executing: %s (type: %s)", monitor.Name, monitor.Type)
	
	// 根据监控类型执行不同的逻辑
	switch monitor.Type {
	case models.MonitorTypeDomain:
		s.executeDomainMonitor(monitor)
	case models.MonitorTypeIP:
		s.executeIPMonitor(monitor)
	case models.MonitorTypeSite:
		s.executeSiteMonitor(monitor)
	case models.MonitorTypeGithub:
		s.executeGithubMonitor(monitor)
	case models.MonitorTypeWIH:
		s.executeWIHMonitor(monitor)
	}
}

// executeDomainMonitor 执行域名监控
func (s *Scheduler) executeDomainMonitor(monitor *models.Monitor) {
	log.Printf("Domain monitor: %s", monitor.Target)
	
	// 查询当前域名解析
	ips, err := net.LookupHost(monitor.Target)
	if err != nil {
		log.Printf("Domain lookup failed: %v", err)
		return
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
}

// executeIPMonitor 执行IP监控
func (s *Scheduler) executeIPMonitor(monitor *models.Monitor) {
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
}

// executeSiteMonitor 执行站点监控
func (s *Scheduler) executeSiteMonitor(monitor *models.Monitor) {
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
		return
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
}

// executeGithubMonitor 执行Github监控
func (s *Scheduler) executeGithubMonitor(monitor *models.Monitor) {
	log.Printf("Github monitor: %s", monitor.Target)
	
	// 创建Github监控器
	githubMonitor := scanner.NewGithubMonitor("")
	
	// 搜索关键字
	result, err := githubMonitor.SearchKeyword(monitor.Target, 10)
	if err != nil {
		log.Printf("Github search failed: %v", err)
		return
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
}

// executeWIHMonitor 执行WIH监控
func (s *Scheduler) executeWIHMonitor(monitor *models.Monitor) {
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
		return
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
}
