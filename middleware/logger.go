package middleware

import (
	"context"
	"time"

	"moongazing/database"
	"moongazing/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// OperationLogMiddleware logs user operations
func OperationLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip logging for GET requests
		if c.Request.Method == "GET" {
			c.Next()
			return
		}
		
		startTime := time.Now()
		
		c.Next()
		
		// Get user info from context
		userID, _ := c.Get("user_id")
		username, _ := c.Get("username")
		
		// Create operation log
		log := models.OperationLog{
			Action:    c.Request.Method,
			Module:    getModuleFromPath(c.Request.URL.Path),
			Target:    c.Request.URL.Path,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Status:    getStatusFromCode(c.Writer.Status()),
			CreatedAt: startTime,
		}
		
		if userID != nil {
			objID, _ := primitive.ObjectIDFromHex(userID.(string))
			log.UserID = objID
		}
		if username != nil {
			log.Username = username.(string)
		}
		
		// Save log asynchronously
		go saveOperationLog(log)
	}
}

func saveOperationLog(log models.OperationLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	collection := database.GetCollection(models.CollectionOperationLog)
	_, _ = collection.InsertOne(ctx, log)
}

func getModuleFromPath(path string) string {
	modules := map[string]string{
		"/api/auth":    "认证",
		"/api/user":    "用户管理",
		"/api/asset":   "资产管理",
		"/api/task":    "任务管理",
		"/api/vuln":    "漏洞管理",
		"/api/node":    "节点管理",
		"/api/plugin":  "插件管理",
		"/api/system":  "系统设置",
	}
	
	for prefix, module := range modules {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return module
		}
	}
	return "其他"
}

func getStatusFromCode(code int) int {
	if code >= 200 && code < 400 {
		return 1
	}
	return 0
}
