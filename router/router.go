package router

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"moongazing/api"
	"moongazing/config"
	"moongazing/middleware"
	"moongazing/service/queue"

	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()
	
	// Middleware
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.OperationLogMiddleware())
	
	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	
	// API routes
	apiGroup := r.Group("/api")
	{
		// Auth routes (no auth required)
		authHandler := api.NewAuthHandler()
		authGroup := apiGroup.Group("/auth")
		{
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/refresh", authHandler.RefreshToken)
		}
		
		// Protected routes
		protected := apiGroup.Group("")
		protected.Use(middleware.AuthMiddleware())
		{
			// Auth routes (auth required)
			protected.POST("/auth/logout", authHandler.Logout)
			protected.GET("/auth/profile", authHandler.GetProfile)
			protected.PUT("/auth/profile", authHandler.UpdateProfile)
			protected.PUT("/auth/password", authHandler.ChangePassword)
			
			// User routes
			userHandler := api.NewUserHandler()
			userGroup := protected.Group("/users")
			{
				userGroup.GET("", middleware.AdminMiddleware(), userHandler.ListUsers)
				userGroup.GET("/:id", userHandler.GetUser)
				userGroup.POST("", middleware.AdminMiddleware(), userHandler.CreateUser)
				userGroup.PUT("/:id", middleware.AdminMiddleware(), userHandler.UpdateUser)
				userGroup.DELETE("/:id", middleware.AdminMiddleware(), userHandler.DeleteUser)
				userGroup.PUT("/:id/status", middleware.AdminMiddleware(), userHandler.SetUserStatus)
				userGroup.PUT("/:id/password", middleware.AdminMiddleware(), userHandler.ResetPassword)
			}
			
			// Asset routes
			assetHandler := api.NewAssetHandler()
			assetGroup := protected.Group("/assets")
			{
				assetGroup.GET("", assetHandler.ListAssets)
				assetGroup.GET("/stats", assetHandler.GetAssetStats)
				assetGroup.GET("/groups", assetHandler.ListAssetGroups)
				assetGroup.POST("/groups", assetHandler.CreateAssetGroup)
				assetGroup.DELETE("/groups/:id", assetHandler.DeleteAssetGroup)
				assetGroup.GET("/blackwhitelist", assetHandler.ListBlackWhiteList)
				assetGroup.POST("/blackwhitelist", assetHandler.CreateBlackWhiteList)
				assetGroup.DELETE("/blackwhitelist/:id", assetHandler.DeleteBlackWhiteList)
				assetGroup.GET("/:id", assetHandler.GetAsset)
				assetGroup.POST("", assetHandler.CreateAsset)
				assetGroup.PUT("/:id", assetHandler.UpdateAsset)
				assetGroup.DELETE("/:id", assetHandler.DeleteAsset)
				assetGroup.POST("/batch-delete", assetHandler.BatchDeleteAssets)
				assetGroup.POST("/:id/tags", assetHandler.AddAssetTags)
				assetGroup.DELETE("/:id/tags", assetHandler.RemoveAssetTags)
			}
			
			// Task routes
			taskHandler := api.NewTaskHandler()
			resultHandler := api.NewResultHandler()
			taskGroup := protected.Group("/tasks")
			{
				taskGroup.GET("", taskHandler.ListTasks)
				taskGroup.GET("/stats", taskHandler.GetTaskStats)
				taskGroup.GET("/templates", taskHandler.ListTaskTemplates)
				taskGroup.GET("/templates/:id", taskHandler.GetTaskTemplate)
				taskGroup.POST("/templates", taskHandler.CreateTaskTemplate)
				taskGroup.DELETE("/templates/:id", taskHandler.DeleteTaskTemplate)
				taskGroup.POST("/from-template", taskHandler.CreateTaskFromTemplate)
				taskGroup.GET("/:id", taskHandler.GetTask)
				taskGroup.POST("", taskHandler.CreateTask)
				taskGroup.PUT("/:id", taskHandler.UpdateTask)
				taskGroup.DELETE("/:id", taskHandler.DeleteTask)
				taskGroup.POST("/:id/start", taskHandler.StartTask)
				taskGroup.POST("/:id/pause", taskHandler.PauseTask)
				taskGroup.POST("/:id/resume", taskHandler.ResumeTask)
				taskGroup.POST("/:id/cancel", taskHandler.CancelTask)
				taskGroup.POST("/:id/retry", taskHandler.RetryTask)
				taskGroup.POST("/:id/rescan", taskHandler.RescanTask)
				taskGroup.GET("/:id/logs", taskHandler.GetTaskLogs)
				// Task Results routes
				taskGroup.GET("/:id/results", resultHandler.GetTaskResults)
				taskGroup.GET("/:id/results/stats", resultHandler.GetTaskResultStats)
				taskGroup.GET("/:id/results/domains", resultHandler.GetDomainResults)
				taskGroup.GET("/:id/results/subdomains", resultHandler.GetSubdomainResults)
				taskGroup.GET("/:id/results/export", resultHandler.ExportResults)
			}
			
			// Results routes (for tag management and batch operations)
			resultGroup := protected.Group("/results")
			{
				resultGroup.PUT("/:id/tags", resultHandler.UpdateResultTags)
				resultGroup.POST("/:id/tags", resultHandler.AddResultTag)
				resultGroup.DELETE("/:id/tags", resultHandler.RemoveResultTag)
				resultGroup.POST("/batch-delete", resultHandler.BatchDeleteResults)
			}
			
			// Vulnerability routes
			vulnHandler := api.NewVulnHandler()
			vulnGroup := protected.Group("/vulnerabilities")
			{
				vulnGroup.GET("", vulnHandler.ListVulnerabilities)
				vulnGroup.GET("/stats", vulnHandler.GetVulnStats)
				vulnGroup.GET("/statistics", vulnHandler.GetVulnStatistics) // 详细统计
				vulnGroup.POST("/batch-update", vulnHandler.BatchUpdateVulnStatus) // 批量更新
				vulnGroup.GET("/:id", vulnHandler.GetVulnerability)
				vulnGroup.POST("", vulnHandler.CreateVulnerability)
				vulnGroup.PUT("/:id", vulnHandler.UpdateVulnerability)
				vulnGroup.DELETE("/:id", vulnHandler.DeleteVulnerability)
				vulnGroup.PUT("/:id/fixed", vulnHandler.MarkVulnAsFixed)
				vulnGroup.PUT("/:id/ignore", vulnHandler.MarkVulnAsIgnored)
				vulnGroup.PUT("/:id/false-positive", vulnHandler.MarkVulnAsFalsePositive)
				vulnGroup.POST("/:id/verify", vulnHandler.VerifyVulnerability) // 验证漏洞
			}
			
			// POC routes
			pocHandler := api.NewPOCHandler()
			pocGroup := protected.Group("/pocs")
			{
				pocGroup.GET("", pocHandler.ListPOCs)
				pocGroup.GET("/statistics", pocHandler.GetPOCStatistics)
				pocGroup.POST("/import", pocHandler.ImportPOCsFromZip)
				pocGroup.POST("/batch-delete", pocHandler.BatchDeletePOCs)
				pocGroup.DELETE("/clear-all", pocHandler.ClearAllPOCs)
				pocGroup.GET("/:id", pocHandler.GetPOC)
				pocGroup.POST("", pocHandler.CreatePOC)
				pocGroup.PUT("/:id", pocHandler.UpdatePOC)
				pocGroup.DELETE("/:id", pocHandler.DeletePOC)
				pocGroup.POST("/:id/toggle", pocHandler.TogglePOCEnabled)
			}
			
			// Report routes
			reportGroup := protected.Group("/reports")
			{
				reportGroup.GET("", vulnHandler.ListReports)
				reportGroup.GET("/:id", vulnHandler.GetReport)
				reportGroup.POST("", vulnHandler.CreateReport)
				reportGroup.DELETE("/:id", vulnHandler.DeleteReport)
			}
			
			// Node routes
			nodeHandler := api.NewNodeHandler()
			nodeGroup := protected.Group("/nodes")
			{
				nodeGroup.GET("", nodeHandler.ListNodes)
				nodeGroup.GET("/stats", nodeHandler.GetNodeStats)
				nodeGroup.POST("/register", nodeHandler.RegisterNode)
				nodeGroup.GET("/:id", nodeHandler.GetNode)
				nodeGroup.PUT("/:id", nodeHandler.UpdateNode)
				nodeGroup.DELETE("/:id", nodeHandler.DeleteNode)
				nodeGroup.POST("/:id/heartbeat", nodeHandler.Heartbeat)
				nodeGroup.PUT("/:id/status", nodeHandler.SetNodeStatus)
			}
			
			// Plugin routes
			pluginHandler := api.NewPluginHandler()
			pluginGroup := protected.Group("/plugins")
			{
				pluginGroup.GET("", pluginHandler.ListPlugins)
				pluginGroup.GET("/:id", pluginHandler.GetPlugin)
				pluginGroup.POST("", pluginHandler.CreatePlugin)
				pluginGroup.PUT("/:id", pluginHandler.UpdatePlugin)
				pluginGroup.DELETE("/:id", pluginHandler.DeletePlugin)
				pluginGroup.PUT("/:id/toggle", pluginHandler.TogglePlugin)
				pluginGroup.POST("/:id/install", pluginHandler.InstallPlugin)
				pluginGroup.POST("/:id/uninstall", pluginHandler.UninstallPlugin)
			}
			
			// Fingerprint routes
			fingerprintGroup := protected.Group("/fingerprints")
			{
				fingerprintGroup.GET("", pluginHandler.ListFingerprintRules)
				fingerprintGroup.POST("", pluginHandler.CreateFingerprintRule)
				fingerprintGroup.DELETE("/:id", pluginHandler.DeleteFingerprintRule)
			}
			
			// Dictionary routes
			dictionaryGroup := protected.Group("/dictionaries")
			{
				dictionaryGroup.GET("", pluginHandler.ListDictionaries)
				dictionaryGroup.POST("", pluginHandler.CreateDictionary)
				dictionaryGroup.DELETE("/:id", pluginHandler.DeleteDictionary)
			}
			
			// Dashboard routes
			dashboardHandler := api.NewDashboardHandler()
			dashboardGroup := protected.Group("/dashboard")
			{
				dashboardGroup.GET("/stats", dashboardHandler.GetDashboardStats)
				dashboardGroup.GET("/trends", dashboardHandler.GetTrends)
				dashboardGroup.GET("/activities", dashboardHandler.GetRecentActivities)
				dashboardGroup.GET("/recent-tasks", dashboardHandler.GetRecentTasks)
				dashboardGroup.GET("/recent-vulns", dashboardHandler.GetRecentVulnerabilities)
				dashboardGroup.GET("/recent-assets", dashboardHandler.GetRecentAssets)
			}

			// Scan routes (实时扫描)
			scanHandler := api.NewScanHandler()
			scanGroup := protected.Group("/scan")
			{
				// 端口扫描
				scanGroup.POST("/port/quick", scanHandler.QuickPortScan)
				scanGroup.POST("/port/custom", scanHandler.CustomPortScan)
				scanGroup.GET("/port/single", scanHandler.SinglePortScan)
				
				// C段扫描
				scanGroup.POST("/csegment", scanHandler.CSegmentScan)
				scanGroup.POST("/csegment/quick", scanHandler.QuickCSegmentScan)
				scanGroup.POST("/csegment/full", scanHandler.FullCSegmentScan)
				
				// 域名扫描
				scanGroup.GET("/domain/info", scanHandler.DomainInfo)
				scanGroup.POST("/subdomain/quick", scanHandler.QuickSubdomainScan)
				scanGroup.POST("/subdomain/full", scanHandler.FullSubdomainScan)
				scanGroup.POST("/subdomain/custom", scanHandler.CustomSubdomainScan)
				
				// CDN检测
				scanGroup.POST("/cdn/detect", scanHandler.CDNDetect)
				scanGroup.POST("/cdn/batch", scanHandler.CDNBatchDetect)
				
				// 指纹识别
				scanGroup.POST("/fingerprint", scanHandler.FingerprintScan)
				scanGroup.POST("/fingerprint/batch", scanHandler.FingerprintBatchScan)
				
				// 漏洞扫描
				scanGroup.POST("/vuln", scanHandler.VulnScan)
				scanGroup.POST("/vuln/quick", scanHandler.VulnQuickScan)
				scanGroup.GET("/vuln/pocs", scanHandler.GetPOCList)
				
				// 目录扫描
				scanGroup.POST("/dir", scanHandler.DirScan)
				scanGroup.POST("/dir/quick", scanHandler.QuickDirScan)
				
				// 敏感信息扫描
				scanGroup.POST("/sensitive", scanHandler.SensitiveScan)
				scanGroup.POST("/sensitive/batch", scanHandler.SensitiveBatchScan)
				
				// 爬虫
				scanGroup.POST("/crawler", scanHandler.CrawlerScan)
				
				// 弱口令扫描
				scanGroup.POST("/weakpwd", scanHandler.WeakPwdScan)

				// 子域名接管检测
				scanGroup.POST("/takeover", scanHandler.TakeoverScan)
				scanGroup.POST("/takeover/batch", scanHandler.TakeoverBatchScan)
				scanGroup.GET("/takeover/fingerprints", scanHandler.GetTakeoverFingerprints)
			}

			// 第三方 API 集成
			thirdPartyHandler := api.NewThirdPartyHandler()
			thirdPartyGroup := protected.Group("/thirdparty")
			{
				// 配置管理
				thirdPartyGroup.GET("/config", thirdPartyHandler.GetConfig)
				thirdPartyGroup.PUT("/config", thirdPartyHandler.UpdateConfig)
				thirdPartyGroup.GET("/sources", thirdPartyHandler.GetConfiguredSources)

				// 统一查询接口
				thirdPartyGroup.POST("/subdomains", thirdPartyHandler.CollectSubdomains)
				thirdPartyGroup.POST("/search/ip", thirdPartyHandler.SearchByIP)
				thirdPartyGroup.POST("/search/cert", thirdPartyHandler.SearchByCert)
				thirdPartyGroup.POST("/search/icon", thirdPartyHandler.SearchByIconHash)
				thirdPartyGroup.POST("/search/title", thirdPartyHandler.SearchByTitle)

				// 证书透明度查询 (免费)
				thirdPartyGroup.GET("/crtsh/subdomains", thirdPartyHandler.GetCertSubdomains)

				// 各平台原生查询
				thirdPartyGroup.POST("/fofa/search", thirdPartyHandler.FofaSearch)
				thirdPartyGroup.POST("/hunter/search", thirdPartyHandler.HunterSearch)
				thirdPartyGroup.POST("/quake/search", thirdPartyHandler.QuakeSearch)
			}

			// 通知管理
			notifyHandler := api.NewNotifyHandler()
			notifyGroup := protected.Group("/notify")
			{
				// 配置管理
				notifyGroup.GET("/types", notifyHandler.GetSupportedTypes)
				notifyGroup.GET("/configs", notifyHandler.GetConfigs)
				notifyGroup.POST("/configs", notifyHandler.AddConfig)
				notifyGroup.PUT("/configs", notifyHandler.UpdateConfig)
				notifyGroup.DELETE("/configs", notifyHandler.DeleteConfig)
				notifyGroup.POST("/configs/enable", notifyHandler.EnableConfig)

				// 测试和发送
				notifyGroup.POST("/test", notifyHandler.TestConfig)
				notifyGroup.POST("/send", notifyHandler.SendNotification)

				// 历史记录
				notifyGroup.GET("/history", notifyHandler.GetHistory)
			}

			// Nuclei POC 扫描
			nucleiHandler := api.NewNucleiHandler()
			nucleiGroup := protected.Group("/nuclei")
			{
				// 模板管理
				nucleiGroup.GET("/templates", nucleiHandler.GetTemplates)
				nucleiGroup.GET("/templates/:id", nucleiHandler.GetTemplate)
				nucleiGroup.POST("/templates", nucleiHandler.UploadTemplate)
				nucleiGroup.DELETE("/templates/:id", nucleiHandler.DeleteTemplate)

				// 统计和管理
				nucleiGroup.GET("/tags", nucleiHandler.GetTags)
				nucleiGroup.GET("/statistics", nucleiHandler.GetStatistics)
				nucleiGroup.POST("/reload", nucleiHandler.ReloadTemplates)
				nucleiGroup.POST("/validate", nucleiHandler.ValidateTemplate)

				// 扫描
				nucleiGroup.POST("/scan", nucleiHandler.ScanTarget)
			}

			// 页面变化监控
			monitorHandler := api.NewMonitorHandler(notifyHandler.GetManager())
			monitorGroup := protected.Group("/monitor")
			{
				// 监控类型
				monitorGroup.GET("/types", monitorHandler.GetMonitorTypes)

				// 页面管理
				monitorGroup.GET("/pages", monitorHandler.ListMonitoredPages)
				monitorGroup.GET("/pages/:id", monitorHandler.GetMonitoredPage)
				monitorGroup.POST("/pages", monitorHandler.AddMonitoredPage)
				monitorGroup.DELETE("/pages/:id", monitorHandler.RemoveMonitoredPage)
				monitorGroup.PUT("/pages/:id/enable", monitorHandler.EnableMonitoredPage)
				monitorGroup.POST("/pages/:id/check", monitorHandler.CheckPageNow)

				// 变化历史
				monitorGroup.GET("/changes", monitorHandler.GetChanges)
			}

			// 自动化巡航任务
			cruiseHandler := api.NewCruiseHandler()
			cruiseGroup := protected.Group("/cruises")
			{
				// 基本 CRUD
				cruiseGroup.GET("", cruiseHandler.ListCruises)
				cruiseGroup.GET("/stats", cruiseHandler.GetCruiseStats)
				cruiseGroup.POST("", cruiseHandler.CreateCruise)
				cruiseGroup.GET("/:id", cruiseHandler.GetCruise)
				cruiseGroup.PUT("/:id", cruiseHandler.UpdateCruise)
				cruiseGroup.DELETE("/:id", cruiseHandler.DeleteCruise)

				// 控制操作
				cruiseGroup.POST("/:id/enable", cruiseHandler.EnableCruise)
				cruiseGroup.POST("/:id/disable", cruiseHandler.DisableCruise)
				cruiseGroup.POST("/:id/run", cruiseHandler.RunNow)

				// 执行日志
				cruiseGroup.GET("/:id/logs", cruiseHandler.GetCruiseLogs)
			}

			// 分布式任务队列 (可选，需要 Redis)
			cfg := config.GetConfig()
			queueConfig := &queue.QueueConfig{
				RedisAddr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
				RedisPassword: cfg.Redis.Password,
				RedisDB:       cfg.Redis.DB,
				QueueName:     "moon-gazing-tower",
				Workers:       cfg.Scanner.WorkerCount,
				TaskTimeout:   time.Duration(cfg.Scanner.Timeout) * time.Second,
				MaxRetries:    cfg.Scanner.RetryCount,
			}

			log.Printf("[Router] Initializing queue with Redis: %s", queueConfig.RedisAddr)
			queueHandler, err := api.NewQueueHandler(queueConfig)
			if err == nil {
				log.Printf("[Router] Queue handler initialized successfully")
				queueGroup := protected.Group("/queue")
				{
					queueGroup.GET("/stats", queueHandler.GetStats)
					queueGroup.GET("/types", queueHandler.GetTaskTypes)
					queueGroup.GET("/workers", queueHandler.GetWorkerStatus)
					queueGroup.POST("/tasks", queueHandler.EnqueueTask)
					queueGroup.GET("/tasks/:id/result", queueHandler.GetTaskResult)
					queueGroup.GET("/tasks/pending", queueHandler.GetPendingTasks)
					queueGroup.GET("/tasks/processing", queueHandler.GetProcessingTasks)
					queueGroup.GET("/tasks/deadletter", queueHandler.GetDeadLetterTasks)
					queueGroup.POST("/tasks/deadletter/:id/retry", queueHandler.RetryDeadLetterTask)
					queueGroup.DELETE("/tasks/deadletter", queueHandler.ClearDeadLetter)
				}
			} else {
				log.Printf("[Router] Queue handler not available (Redis connection failed): %v", err)
			}
		}
	}
	
	// 配置静态文件服务
	SetupStaticFiles(r)
	
	return r
}

func SetupRouterWithWebSocket(hub *api.Hub) *gin.Engine {
	r := SetupRouter()

	// Register WebSocket routes
	RegisterWebSocketRoutes(r, hub)

	return r
}

func RegisterWebSocketRoutes(router *gin.Engine, hub *api.Hub) {
	// WebSocket endpoint for real-time data
	router.GET("/api/ws", hub.WebSocketHandler)
}

// SetupStaticFiles 配置静态文件服务
func SetupStaticFiles(r *gin.Engine) {
	// 获取可执行文件所在目录
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("[Router] Failed to get executable path: %v", err)
		return
	}
	execDir := filepath.Dir(execPath)
	
	// 尝试多个可能的 web 目录路径
	possiblePaths := []string{
		filepath.Join(execDir, "web"),       // 可执行文件同目录
		"web",                                // 当前工作目录
		"./web",                              // 当前工作目录
		filepath.Join(execDir, "..", "web"), // 上级目录
	}
	
	var webDir string
	for _, path := range possiblePaths {
		if _, err := os.Stat(filepath.Join(path, "index.html")); err == nil {
			webDir = path
			break
		}
	}
	
	if webDir == "" {
		log.Printf("[Router] Web directory not found, static files will not be served")
		return
	}
	
	log.Printf("[Router] Serving static files from: %s", webDir)
	
	// 静态资源目录
	assetsDir := filepath.Join(webDir, "assets")
	if _, err := os.Stat(assetsDir); err == nil {
		r.Static("/assets", assetsDir)
	}
	
	// 其他静态文件（favicon, robots.txt 等）
	r.StaticFile("/favicon.ico", filepath.Join(webDir, "favicon.ico"))
	r.StaticFile("/robots.txt", filepath.Join(webDir, "robots.txt"))
	
	// SPA 路由处理 - 所有非 API 路由返回 index.html
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		
		// 如果是 API 路径，返回 404
		if strings.HasPrefix(path, "/api") {
			c.JSON(404, gin.H{"code": 404, "message": "API not found"})
			return
		}
		
		// 如果是静态资源路径且文件存在，直接返回
		if strings.HasPrefix(path, "/assets") {
			filePath := filepath.Join(webDir, path)
			if _, err := os.Stat(filePath); err == nil {
				c.File(filePath)
				return
			}
		}
		
		// 检查请求的文件是否存在
		filePath := filepath.Join(webDir, path)
		if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
			c.File(filePath)
			return
		}
		
		// SPA 路由回退到 index.html
		indexPath := filepath.Join(webDir, "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			c.File(indexPath)
			return
		}
		
		c.JSON(404, gin.H{"code": 404, "message": "Not found"})
	})
}

// EmbedStaticFiles 使用嵌入的静态文件（可选，用于单文件部署）
func EmbedStaticFiles(r *gin.Engine, webFS fs.FS) {
	// 静态资源
	assetsFS, err := fs.Sub(webFS, "assets")
	if err == nil {
		r.StaticFS("/assets", http.FS(assetsFS))
	}
	
	// index.html 和 SPA 路由
	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		
		if strings.HasPrefix(path, "/api") {
			c.JSON(404, gin.H{"code": 404, "message": "API not found"})
			return
		}
		
		// 尝试读取请求的文件
		if !strings.HasPrefix(path, "/assets") {
			content, err := fs.ReadFile(webFS, "index.html")
			if err == nil {
				c.Data(200, "text/html; charset=utf-8", content)
				return
			}
		}
		
		c.JSON(404, gin.H{"code": 404, "message": "Not found"})
	})
}
