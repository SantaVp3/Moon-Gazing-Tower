package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/scanner"
)

// TaskService 任务服务
type TaskService struct {
	scanEngine      *scanner.Engine
	runningTasks    map[string]context.CancelFunc
	runningTasksMux sync.RWMutex
}

// NewTaskService 创建任务服务
func NewTaskService() *TaskService {
	return &TaskService{
		scanEngine:   scanner.NewEngine(),
		runningTasks: make(map[string]context.CancelFunc),
	}
}

// CancelTask 取消正在运行的任务
func (s *TaskService) CancelTask(taskID string) error {
	s.runningTasksMux.Lock()
	defer s.runningTasksMux.Unlock()

	if cancelFunc, exists := s.runningTasks[taskID]; exists {
		log.Printf("Cancelling task %s", taskID)
		cancelFunc() // 调用取消函数
		delete(s.runningTasks, taskID)
		return nil
	}

	return fmt.Errorf("task %s is not running", taskID)
}

// ExecuteTask 执行任务
func (s *TaskService) ExecuteTask(taskID string) {
	log.Printf("========== ExecuteTask called for task: %s ==========", taskID)
	
	// 获取任务
	var task models.Task
	if err := database.DB.First(&task, "id = ?", taskID).Error; err != nil {
		log.Printf("Failed to find task %s: %v", taskID, err)
		return
	}
	
	log.Printf("Task found: ID=%s, Name=%s, Target=%s", task.ID, task.Name, task.Target)
	log.Printf("Task options: EnablePortScan=%v, PortScanType=%s", 
		task.Options.EnablePortScan, task.Options.PortScanType)

	// 创建可取消的context
	ctx, cancel := context.WithCancel(context.Background())
	
	// 注册到运行任务列表
	s.runningTasksMux.Lock()
	s.runningTasks[taskID] = cancel
	s.runningTasksMux.Unlock()
	
	// 任务结束后清理
	defer func() {
		s.runningTasksMux.Lock()
		delete(s.runningTasks, taskID)
		s.runningTasksMux.Unlock()
	}()

	// 更新任务状态为运行中
	now := time.Now()
	task.Status = models.TaskStatusRunning
	task.StartedAt = &now
	task.Progress = 0
	database.DB.Save(&task)

	log.Printf("Starting task %s: %s", task.ID, task.Name)

	// 执行扫描
	err := s.executeScanner(ctx, &task)

	// 更新任务状态
	endTime := time.Now()
	task.EndedAt = &endTime
	
	// 检查是否被取消
	if ctx.Err() == context.Canceled {
		task.Status = models.TaskStatusCancelled
		task.ErrorMsg = "Task was cancelled by user"
		log.Printf("Task %s was cancelled", task.ID)
	} else if err != nil {
		task.Status = models.TaskStatusFailed
		task.ErrorMsg = err.Error()
		log.Printf("Task %s failed: %v", task.ID, err)
	} else {
		task.Status = models.TaskStatusCompleted
		task.Progress = 100
		log.Printf("Task %s completed successfully", task.ID)
	}

	database.DB.Save(&task)
}

// executeScanner 执行扫描引擎
func (s *TaskService) executeScanner(ctx context.Context, task *models.Task) error {
	scanCtx := &scanner.ScanContext{
		Task:   task,
		DB:     database.DB,
		Logger: log.Default(),
		Ctx:    ctx, // 传递取消context
	}

	// 检查任务是否已被取消的辅助函数
	checkCancelled := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	// 0. 被动扫描（如果启用）
	if task.Options.EnablePassiveScan {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Starting passive scan", task.ID)
		if err := s.scanEngine.RunPassiveScan(scanCtx); err != nil {
			log.Printf("Passive scan failed: %v", err) // 不中断任务
		}
		s.updateProgress(task, 10)
	}

	// 1. 域名发现
	if task.Options.EnableDomainBrute || task.Options.EnableDomainPlugins {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Starting domain discovery", task.ID)
		if err := s.scanEngine.DiscoverDomains(scanCtx); err != nil {
			return fmt.Errorf("domain discovery failed: %w", err)
		}
		s.updateProgress(task, 20)
	}

	// 2. IP解析
	if err := checkCancelled(); err != nil {
		return err
	}
	log.Printf("Task %s: Starting IP resolution", task.ID)
	if err := s.scanEngine.ResolveIPs(scanCtx); err != nil {
		return fmt.Errorf("IP resolution failed: %w", err)
	}
	s.updateProgress(task, 35)

	// 2.5. C段扫描
	if task.Options.EnableCSegment {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Starting C segment scanning", task.ID)
		if err := s.scanEngine.ScanCSegment(scanCtx); err != nil {
			log.Printf("C segment scanning failed: %v", err) // 不中断任务
		}
	}
	s.updateProgress(task, 40)

	// 3. 端口扫描
	if task.Options.EnablePortScan {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Starting port scan", task.ID)
		if err := s.scanEngine.ScanPorts(scanCtx); err != nil {
			return fmt.Errorf("port scan failed: %w", err)
		}
		s.updateProgress(task, 60)
	}

	// 4. 服务识别
	if task.Options.EnableServiceDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Starting service detection", task.ID)
		if err := s.scanEngine.DetectServices(scanCtx); err != nil {
			return fmt.Errorf("service detection failed: %w", err)
		}
		s.updateProgress(task, 70)
	}

	// 5. 站点识别
	if task.Options.EnableSiteDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Starting site detection", task.ID)
		if err := s.scanEngine.DetectSites(scanCtx); err != nil {
			return fmt.Errorf("site detection failed: %w", err)
		}
		s.updateProgress(task, 80)
	}

	// 6. 操作系统识别
	if task.Options.EnableOSDetect {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Detecting OS", task.ID)
		if err := s.scanEngine.DetectOS(scanCtx); err != nil {
			log.Printf("OS detection failed: %v", err)
		}
	}

	// 7. 站点截图
	if task.Options.EnableScreenshot {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Taking screenshots", task.ID)
		if err := s.scanEngine.TakeScreenshots(scanCtx); err != nil {
			log.Printf("Screenshot failed: %v", err) // 不中断任务
		}
	}

	s.updateProgress(task, 85)

	// 8. 漏洞检测
	if task.Options.EnableFileLeak {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Checking file leaks", task.ID)
		if err := s.scanEngine.CheckFileLeaks(scanCtx); err != nil {
			log.Printf("File leak check failed: %v", err) // 不中断任务
		}
	}

	s.updateProgress(task, 90)

	// 9. Host碰撞检测
	if task.Options.EnableHostCollision {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Checking host collision", task.ID)
		if err := s.scanEngine.CheckHostCollision(scanCtx); err != nil {
			log.Printf("Host collision check failed: %v", err)
		}
	}

	// 9.5. 子域名接管检测
	if err := checkCancelled(); err != nil {
		return err
	}
	log.Printf("Task %s: Checking subdomain takeover", task.ID)
	if err := s.scanEngine.CheckSubdomainTakeover(scanCtx); err != nil {
		log.Printf("Subdomain takeover check failed: %v", err)
	}

	// 10. 智能PoC检测 (基于指纹匹配,替代Nuclei/XPOC/Afrog)
	if task.Options.EnablePoCDetection {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Running smart PoC detection with fingerprint matching", task.ID)
		if err := s.scanEngine.RunPoCScanning(scanCtx); err != nil {
			log.Printf("PoC scanning failed: %v", err) // 不中断任务
		}
	}

	s.updateProgress(task, 92)

	// 13. 自定义脚本
	if task.Options.EnableCustomScript && task.Options.CustomScriptPath != "" {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Running custom script: %s", task.ID, task.Options.CustomScriptPath)
		if err := s.runCustomScript(scanCtx); err != nil {
			log.Printf("Custom script failed: %v", err) // 不中断任务
		}
	}

	s.updateProgress(task, 96)

	// 14. WebInfoHunter (如果启用)
	if task.Options.EnableWIH {
		if err := checkCancelled(); err != nil {
			return err
		}
		log.Printf("Task %s: Running WebInfoHunter", task.ID)
		if err := s.runWebInfoHunter(scanCtx); err != nil {
			log.Printf("WebInfoHunter failed: %v", err)
		}
	}

	s.updateProgress(task, 98)

	// 15. 资产测绘（最后执行，生成资产画像）
	if err := checkCancelled(); err != nil {
		return err
	}
	log.Printf("Task %s: Mapping assets", task.ID)
	if err := s.scanEngine.MapAssets(scanCtx); err != nil {
		log.Printf("Asset mapping failed: %v", err)
	}

	s.updateProgress(task, 100)
	return nil
}

// runCustomScript 运行自定义脚本
func (s *TaskService) runCustomScript(ctx *scanner.ScanContext) error {
	scriptPath := ctx.Task.Options.CustomScriptPath
	
	// 直接当作脚本路径处理
	return s.scanEngine.RunCustomScript(ctx, scriptPath)
}

// runWebInfoHunter 运行WebInfoHunter
func (s *TaskService) runWebInfoHunter(ctx *scanner.ScanContext) error {
	// 获取所有站点
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	if len(sites) == 0 {
		return nil
	}

	urls := make([]string, len(sites))
	for i, site := range sites {
		urls[i] = site.URL
	}

	// 创建WIH扫描器
	wih := scanner.NewWebInfoHunter("")
	
	// 执行扫描
	results, err := wih.Scan(ctx, urls)
	if err != nil {
		return err
	}

	// 保存结果
	return wih.SaveResults(ctx, results)
}

// takeScreenshots 站点截图
func (s *TaskService) takeScreenshots(ctx *scanner.ScanContext) error {
	// 获取所有站点
	var sites []models.Site
	ctx.DB.Where("task_id = ?", ctx.Task.ID).Find(&sites)

	if len(sites) == 0 {
		return nil
	}

	ctx.Logger.Printf("Taking screenshots for %d sites", len(sites))

	// 创建截图扫描器
	screenshotScanner := scanner.NewScreenshotScanner("./screenshots")

	// 批量截图（并发5个）
	urls := make([]string, len(sites))
	for i, site := range sites {
		urls[i] = site.URL
	}

	results := screenshotScanner.BatchScreenshot(urls, 5)

	// 更新站点记录
	for _, site := range sites {
		if filepath, ok := results[site.URL]; ok && filepath != "" {
			site.Screenshot = filepath
			ctx.DB.Save(&site)
			ctx.Logger.Printf("Screenshot saved: %s -> %s", site.URL, filepath)
		}
	}

	return nil
}

// updateProgress 更新任务进度
func (s *TaskService) updateProgress(task *models.Task, progress int) {
	database.DB.Model(task).Update("progress", progress)
}
