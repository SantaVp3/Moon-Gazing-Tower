package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/reconmaster/backend/internal/scanner"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源（生产环境应该限制）
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// WebSocketHandler WebSocket处理器
type WebSocketHandler struct {
	clients      map[*websocket.Conn]string // conn -> taskID
	clientsMutex sync.RWMutex
	progressChans map[string]chan *scanner.ScanProgress // taskID -> progress channel
	chansMutex   sync.RWMutex
}

// NewWebSocketHandler 创建WebSocket处理器
func NewWebSocketHandler() *WebSocketHandler {
	handler := &WebSocketHandler{
		clients:       make(map[*websocket.Conn]string),
		progressChans: make(map[string]chan *scanner.ScanProgress),
	}
	
	// 启动进度分发器
	go handler.progressDispatcher()
	
	return handler
}

// HandleWebSocket 处理WebSocket连接
func (h *WebSocketHandler) HandleWebSocket(c *gin.Context) {
	taskID := c.Query("task_id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task_id is required"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// 注册客户端
	h.clientsMutex.Lock()
	h.clients[conn] = taskID
	h.clientsMutex.Unlock()

	log.Printf("WebSocket client connected for task: %s", taskID)

	// 发送欢迎消息
	welcomeMsg := map[string]interface{}{
		"type":    "connected",
		"task_id": taskID,
		"message": "WebSocket connected successfully",
		"time":    time.Now().Format(time.RFC3339),
	}
	if err := conn.WriteJSON(welcomeMsg); err != nil {
		log.Printf("Failed to send welcome message: %v", err)
	}

	// 保持连接并处理客户端消息
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		// 处理ping/pong等心跳消息
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err == nil {
			if msgType, ok := msg["type"].(string); ok && msgType == "ping" {
				pongMsg := map[string]interface{}{
					"type": "pong",
					"time": time.Now().Format(time.RFC3339),
				}
				if err := conn.WriteJSON(pongMsg); err != nil {
					log.Printf("Failed to send pong: %v", err)
					break
				}
			}
		}
	}

	// 清理客户端
	h.clientsMutex.Lock()
	delete(h.clients, conn)
	h.clientsMutex.Unlock()

	log.Printf("WebSocket client disconnected for task: %s", taskID)
}

// RegisterProgressChannel 注册任务的进度通道
func (h *WebSocketHandler) RegisterProgressChannel(taskID string, ch chan *scanner.ScanProgress) {
	h.chansMutex.Lock()
	h.progressChans[taskID] = ch
	h.chansMutex.Unlock()
	log.Printf("Progress channel registered for task: %s", taskID)
}

// UnregisterProgressChannel 注销任务的进度通道
func (h *WebSocketHandler) UnregisterProgressChannel(taskID string) {
	h.chansMutex.Lock()
	if ch, exists := h.progressChans[taskID]; exists {
		close(ch)
		delete(h.progressChans, taskID)
	}
	h.chansMutex.Unlock()
	log.Printf("Progress channel unregistered for task: %s", taskID)
}

// progressDispatcher 进度分发器 - 从进度通道读取并广播给WebSocket客户端
func (h *WebSocketHandler) progressDispatcher() {
	ticker := time.NewTicker(100 * time.Millisecond) // 每100ms检查一次
	defer ticker.Stop()

	for range ticker.C {
		h.chansMutex.RLock()
		for taskID, progressChan := range h.progressChans {
			// 非阻塞读取进度
			select {
			case progress, ok := <-progressChan:
				if !ok {
					// 通道已关闭
					continue
				}
				// 广播进度到所有订阅该任务的客户端
				h.broadcastProgress(taskID, progress)
			default:
				// 没有新进度，跳过
			}
		}
		h.chansMutex.RUnlock()
	}
}

// broadcastProgress 广播进度到指定任务的所有客户端
func (h *WebSocketHandler) broadcastProgress(taskID string, progress *scanner.ScanProgress) {
	h.clientsMutex.RLock()
	defer h.clientsMutex.RUnlock()

	message := map[string]interface{}{
		"type":         "progress",
		"task_id":      taskID,
		"stage":        progress.Stage,
		"current":      progress.Current,
		"total":        progress.Total,
		"percentage":   progress.Percentage,
		"speed":        progress.Speed,
		"open_ports":   progress.OpenPorts,
		"elapsed_time": progress.ElapsedTime,
		"eta":          progress.ETA,
		"message":      progress.Message,
		"timestamp":    progress.Timestamp.Format(time.RFC3339),
	}

	for conn, connTaskID := range h.clients {
		if connTaskID == taskID {
			if err := conn.WriteJSON(message); err != nil {
				log.Printf("Failed to send progress to client: %v", err)
			}
		}
	}
}

// BroadcastTaskComplete 广播任务完成消息
func (h *WebSocketHandler) BroadcastTaskComplete(taskID string, status string, message string) {
	h.clientsMutex.RLock()
	defer h.clientsMutex.RUnlock()

	completeMsg := map[string]interface{}{
		"type":    "task_complete",
		"task_id": taskID,
		"status":  status,
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	}

	for conn, connTaskID := range h.clients {
		if connTaskID == taskID {
			if err := conn.WriteJSON(completeMsg); err != nil {
				log.Printf("Failed to send task complete message: %v", err)
			}
		}
	}
}

// GetProgressChannel 获取或创建任务的进度通道
func (h *WebSocketHandler) GetProgressChannel(taskID string) chan *scanner.ScanProgress {
	h.chansMutex.Lock()
	defer h.chansMutex.Unlock()

	if ch, exists := h.progressChans[taskID]; exists {
		return ch
	}

	ch := make(chan *scanner.ScanProgress, 100)
	h.progressChans[taskID] = ch
	return ch
}
