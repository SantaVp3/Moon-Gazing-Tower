package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"moongazing/service"
	"moongazing/utils"
)

// WebSocketHandler handles WebSocket connections for real-time data
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from any origin (configure appropriately for production)
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Client represents a WebSocket client
type Client struct {
	conn      *websocket.Conn
	send      chan []byte
	hub       *Hub
	clientID  string
	userID    string
	workspaceID string
}

// Hub maintains the active clients and broadcasts messages
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// NewHub creates a new Hub
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the Hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// StartMonitorTask starts broadcasting monitoring data
func (h *Hub) StartMonitorTask() {
	ticker := time.NewTicker(5 * time.Second) // Update every 5 seconds
	defer ticker.Stop()

	sysService := service.NewSystemService()
	nodeService := service.NewNodeService()

	for {
		select {
		case <-ticker.C:
			monitorData := h.getMonitorData(sysService, nodeService)
			data, _ := json.Marshal(monitorData)
			h.broadcast <- data
		}
	}
}

// getMonitorData collects real-time monitoring data
func (h *Hub) getMonitorData(sysService *service.SystemService, nodeService *service.NodeService) map[string]interface{} {
	sysInfo, _ := sysService.GetSystemInfo("")
	nodeStats, _ := nodeService.GetNodeStats()

	return map[string]interface{}{
		"type": "monitor_data",
		"timestamp": time.Now().Unix(),
		"system": map[string]interface{}{
			"cpu_usage":         sysInfo["cpu_usage"],
			"memory_usage":      sysInfo["memory_usage"],
			"memory_total":      sysInfo["memory_total"],
			"memory_used":       sysInfo["memory_used"],
			"disk_usage":        sysInfo["disk_usage"],
			"disk_total":        sysInfo["disk_total"],
			"disk_used":         sysInfo["disk_used"],
		},
		"nodes": map[string]interface{}{
			"total":         nodeStats["total"],
			"online":        nodeStats["online"],
			"offline":       nodeStats["offline"],
		},
		"analytics": map[string]interface{}{
			"monthly_users":        0,
			"monthly_spend":        0,
			"monthly_revenue":      0,
			"monthly_transactions": 0,
		},
	}
}

// WebSocketHandler handles WebSocket connections
func (h *Hub) WebSocketHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		utils.Error(c, utils.ErrCodeInvalidParams, "WebSocket upgrade failed")
		return
	}

	client := &Client{
		conn:      conn,
		send:      make(chan []byte, 256),
		hub:       h,
		clientID:  "", // Generate unique client ID
		userID:    "", // Extract from JWT/auth
		workspaceID: c.Query("workspace_id"),
	}

	client.hub.register <- client

	go client.writePump()
	client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(65536) // 64KB
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket unexpected close: %v", err)
			}
			break
		}

		// Handle client messages (pings, commands, etc.)
		var msg map[string]string
		if err := json.Unmarshal(message, &msg); err == nil {
			if msg["type"] == "ping" {
				c.send <- []byte(`{"type":"pong"}`)
			}
		}

		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket ping error: %v", err)
				return
			}
		}
	}
}