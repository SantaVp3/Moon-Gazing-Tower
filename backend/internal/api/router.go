package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/api/handlers"
	"github.com/reconmaster/backend/internal/middleware"
	"github.com/reconmaster/backend/internal/services"
)

// SetupRouter 设置路由
func SetupRouter(taskService *services.TaskService) *gin.Engine {
	router := gin.Default()

	// 设置信任的代理 - 不信任任何代理（如果在代理后运行，请修改此配置）
	router.SetTrustedProxies(nil)

	// CORS配置
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// WebSocket处理器（全局单例）
	wsHandler := handlers.NewWebSocketHandler()
	
	// 将 WebSocket handler 传递给 taskService
	taskService.SetWebSocketHandler(wsHandler)

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 静态文件服务 - 前端页面
	router.Static("/assets", "./web/dist/assets")
	router.StaticFile("/logo.svg", "./web/dist/logo.svg")
	router.StaticFile("/logo-icon.svg", "./web/dist/logo-icon.svg")

	// 静态文件服务 - 提供截图访问（需要认证）
	router.Static("/screenshots", "./data/screenshots")

	// 认证接口（不需要token）
	authHandler := handlers.NewAuthHandler()
	auth := router.Group("/api/v1/auth")
	{
		auth.POST("/login", authHandler.Login)
		auth.POST("/register", authHandler.Register)
	}

	// WebSocket endpoint（不需要认证，但需要task_id验证）
	router.GET("/api/v1/ws/progress", wsHandler.HandleWebSocket)

	// API v1（需要认证）
	v1 := router.Group("/api/v1")
	v1.Use(middleware.AuthRequired())
	{
		// 任务管理
		taskHandler := handlers.NewTaskHandler(taskService)
		tasks := v1.Group("/tasks")
		{
			tasks.POST("", taskHandler.CreateTask)
			tasks.GET("", taskHandler.ListTasks)
			tasks.GET("/:id", taskHandler.GetTask)
			tasks.DELETE("/:id", taskHandler.DeleteTask)
			tasks.POST("/:id/start", taskHandler.StartTask)   // 手动启动任务
			tasks.POST("/:id/cancel", taskHandler.CancelTask)
			tasks.GET("/stats", taskHandler.GetTaskStats)
			tasks.POST("/batch/delete", taskHandler.BatchDeleteTasks) //  批量删除
		}

		// 资产管理
		assetHandler := handlers.NewAssetHandler()
		assetProfileHandler := handlers.NewAssetProfileHandler()
		assets := v1.Group("/assets")
		{
			assets.GET("/domains", assetHandler.ListDomains)
			assets.GET("/ips", assetHandler.ListIPs)
			assets.GET("/ports", assetHandler.ListPorts)
			assets.GET("/sites", assetHandler.ListSites)
			assets.GET("/urls", assetHandler.ListURLs)
			assets.GET("/vulnerabilities", assetHandler.ListVulnerabilities)
			assets.GET("/stats", assetHandler.GetAssetStats)
			
			// 资产画像
			assets.GET("/profile", assetProfileHandler.GetAssetProfile)
			assets.GET("/relations", assetProfileHandler.GetAssetRelations)
			assets.GET("/graph", assetProfileHandler.GetAssetGraph)
			assets.GET("/c-segment", assetProfileHandler.AnalyzeCSegment)
		}
		
		// 资产标签
		assetTagHandler := handlers.NewAssetTagHandler()
		tags := v1.Group("/tags")
		{
			tags.GET("", assetTagHandler.ListTags)
			tags.POST("", assetTagHandler.CreateTag)
			tags.PUT("/:id", assetTagHandler.UpdateTag)
			tags.DELETE("/:id", assetTagHandler.DeleteTag)
			tags.GET("/:id/stats", assetTagHandler.GetTagStats)
			tags.POST("/attach", assetTagHandler.AddAssetTags)
			tags.GET("/asset", assetTagHandler.GetAssetTags)
			tags.GET("/search", assetTagHandler.SearchAssetsByTag)
		}

		// 监控管理
		monitorHandler := handlers.NewMonitorHandler()
		monitors := v1.Group("/monitors")
		{
			monitors.POST("", monitorHandler.CreateMonitor)
			monitors.GET("", monitorHandler.ListMonitors)
			monitors.GET("/:id", monitorHandler.GetMonitor)
			monitors.PATCH("/:id/status", monitorHandler.UpdateMonitorStatus)
			monitors.DELETE("/:id", monitorHandler.DeleteMonitor)
			monitors.GET("/:id/results", monitorHandler.ListMonitorResults)
		}

		// 导出管理
		exportHandler := handlers.NewExportHandler()
		exports := v1.Group("/export")
		{
			exports.GET("/task/:id", exportHandler.ExportTask)
			exports.GET("/download", exportHandler.DownloadExport)
		}

		// 用户管理
		users := v1.Group("/users")
		{
			users.GET("/me", authHandler.GetCurrentUser)
			users.PUT("/me", authHandler.UpdateProfile)
			users.PUT("/me/password", authHandler.UpdatePassword)
			users.POST("/logout", authHandler.Logout)

			// 管理员接口
			admin := users.Group("")
			admin.Use(middleware.AdminRequired())
			{
				admin.GET("", authHandler.ListUsers)
				admin.PATCH("/:id/status", authHandler.UpdateUserStatus)
			}
		}

		// 系统设置（管理员权限）
		settingHandler := handlers.NewSettingHandler()
		settings := v1.Group("/settings")
		settings.Use(middleware.AdminRequired())
		{
			settings.GET("", settingHandler.GetSettings)
			settings.GET("/:key", settingHandler.GetSetting)
			settings.POST("", settingHandler.UpdateSetting)
			settings.POST("/batch", settingHandler.BatchUpdateSettings)
			settings.DELETE("/:key", settingHandler.DeleteSetting)
		}

		// 字典管理
		dictionaries := v1.Group("/dictionaries")
		{
			// 所有用户都可以查看字典列表
			dictionaries.GET("", settingHandler.ListDictionaries)

			// 以下操作需要管理员权限
			admin := dictionaries.Group("")
			admin.Use(middleware.AdminRequired())
			{
				admin.POST("/upload", settingHandler.UploadDictionary)
				admin.DELETE("/:id", settingHandler.DeleteDictionary)
				admin.POST("/:id/default", settingHandler.SetDefaultDictionary)
			}
		}

		// 指纹管理
		fingerprintHandler := handlers.NewFingerprintHandler()
		fingerprints := v1.Group("/fingerprints")
		{
			// 特定路径的路由要放在前面
			fingerprints.GET("/categories", fingerprintHandler.GetCategories)
			fingerprints.POST("/batch", fingerprintHandler.BatchCreateFingerprints)
			fingerprints.POST("/import", fingerprintHandler.ImportFingerprints) // 导入接口

			// 通用路由放在后面
			fingerprints.GET("", fingerprintHandler.ListFingerprints)
			fingerprints.POST("", fingerprintHandler.CreateFingerprint)
			fingerprints.GET("/:id", fingerprintHandler.GetFingerprint)
			fingerprints.PUT("/:id", fingerprintHandler.UpdateFingerprint)
			fingerprints.DELETE("/:id", fingerprintHandler.DeleteFingerprint)
		}

		// PoC管理
		pocHandler := handlers.NewPoCHandler()
		pocs := v1.Group("/pocs")
		{
			pocs.GET("", pocHandler.ListPoCs)
			pocs.GET("/:id", pocHandler.GetPoC)
			pocs.POST("", pocHandler.CreatePoC)
			pocs.PUT("/:id", pocHandler.UpdatePoC)
			pocs.DELETE("/:id", pocHandler.DeletePoC)
			pocs.POST("/:id/toggle", pocHandler.TogglePoCStatus)
			pocs.POST("/:id/execute", pocHandler.ExecutePoC)
			pocs.POST("/batch", pocHandler.BatchImportPoCs)
			pocs.POST("/import", pocHandler.BatchImportPoCs) // 添加 /import 路由，指向同一个handler
			pocs.GET("/categories", pocHandler.GetPoCCategories)
			pocs.GET("/stats", pocHandler.GetPoCStats)
		}

		// GitHub监控
		githubHandler := handlers.NewGitHubMonitorHandler()
		github := v1.Group("/github-monitors")
		{
			github.GET("", githubHandler.ListGitHubMonitors)
			github.GET("/:id", githubHandler.GetGitHubMonitor)
			github.POST("", githubHandler.CreateGitHubMonitor)
			github.PUT("/:id", githubHandler.UpdateGitHubMonitor)
			github.DELETE("/:id", githubHandler.DeleteGitHubMonitor)
			github.POST("/:id/toggle", githubHandler.ToggleGitHubMonitorStatus)
			github.POST("/:id/run", githubHandler.RunGitHubMonitor)
			github.GET("/:id/results", githubHandler.ListGitHubMonitorResults)
			github.POST("/results/:result_id/read", githubHandler.MarkResultAsRead)
			github.GET("/stats", githubHandler.GetGitHubMonitorStats)
		}

		// 计划任务
		scheduledTaskHandler := handlers.NewScheduledTaskHandler()
		scheduledTasks := v1.Group("/scheduled-tasks")
		{
			scheduledTasks.GET("", scheduledTaskHandler.ListScheduledTasks)
			scheduledTasks.GET("/:id", scheduledTaskHandler.GetScheduledTask)
			scheduledTasks.POST("", scheduledTaskHandler.CreateScheduledTask)
			scheduledTasks.PUT("/:id", scheduledTaskHandler.UpdateScheduledTask)
			scheduledTasks.DELETE("/:id", scheduledTaskHandler.DeleteScheduledTask)
			scheduledTasks.POST("/:id/toggle", scheduledTaskHandler.ToggleScheduledTaskStatus)
			scheduledTasks.POST("/:id/run", scheduledTaskHandler.RunScheduledTaskNow)
			scheduledTasks.GET("/:id/logs", scheduledTaskHandler.GetScheduledTaskLogs)
			scheduledTasks.GET("/stats", scheduledTaskHandler.GetScheduledTaskStats)
			scheduledTasks.POST("/batch/delete", scheduledTaskHandler.BatchDeleteScheduledTasks)
			scheduledTasks.POST("/batch/toggle", scheduledTaskHandler.BatchToggleScheduledTasks)
		}

		// 策略配置
		policyHandler := handlers.NewPolicyHandler()
		policies := v1.Group("/policies")
		{
			policies.GET("", policyHandler.ListPolicies)
			policies.GET("/:id", policyHandler.GetPolicy)
			policies.POST("", policyHandler.CreatePolicy)
			policies.PUT("/:id", policyHandler.UpdatePolicy)
			policies.DELETE("/:id", policyHandler.DeletePolicy)
			policies.POST("/:id/set-default", policyHandler.SetDefaultPolicy)
			policies.GET("/default", policyHandler.GetDefaultPolicy)
			policies.POST("/batch/delete", policyHandler.BatchDelete)
			policies.GET("/stats", policyHandler.GetStats)
		}
	}

	// 前端路由 - 所有非API请求都返回index.html（支持前端路由）
	router.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})

	return router
}
