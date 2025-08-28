package websocket

import (
	"encoding/json"
	"log"
	"net/http"

	"stackguard-task/internal/models"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

type Hub struct {
	clients       map[*websocket.Conn]bool
	alertClients  map[*websocket.Conn]bool
	broadcast     chan []byte
	alertBroadcast chan []byte
	register      chan *websocket.Conn
	alertRegister chan *websocket.Conn
	unregister    chan *websocket.Conn
	alertUnregister chan *websocket.Conn
}

func NewHub() *Hub {
	return &Hub{
		clients:         make(map[*websocket.Conn]bool),
		alertClients:    make(map[*websocket.Conn]bool),
		broadcast:       make(chan []byte, 256),
		alertBroadcast:  make(chan []byte, 256),
		register:        make(chan *websocket.Conn, 10),
		alertRegister:   make(chan *websocket.Conn, 10),
		unregister:      make(chan *websocket.Conn, 10),
		alertUnregister: make(chan *websocket.Conn, 10),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			log.Printf("WebSocket client connected. Total clients: %d", len(h.clients))

		case client := <-h.alertRegister:
			h.alertClients[client] = true
			log.Printf("Alert WebSocket client connected. Total alert clients: %d", len(h.alertClients))

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
				log.Printf("WebSocket client disconnected. Total clients: %d", len(h.clients))
			}

		case client := <-h.alertUnregister:
			if _, ok := h.alertClients[client]; ok {
				delete(h.alertClients, client)
				client.Close()
				log.Printf("Alert WebSocket client disconnected. Total alert clients: %d", len(h.alertClients))
			}

		case message := <-h.broadcast:
			for client := range h.clients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					log.Printf("WebSocket write error: %v", err)
					delete(h.clients, client)
					client.Close()
				}
			}

		case message := <-h.alertBroadcast:
			for client := range h.alertClients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					log.Printf("Alert WebSocket write error: %v", err)
					delete(h.alertClients, client)
					client.Close()
				}
			}
		}
	}
}

func (h *Hub) BroadcastDetection(detection models.SecretDetection) {
	jsonData, err := json.Marshal(detection)
	if err != nil {
		log.Printf("Error marshaling detection for WebSocket: %v", err)
		return
	}

	select {
	case h.broadcast <- jsonData:
	default:
		log.Printf("WebSocket broadcast channel full, dropping message")
	}
}

func (h *Hub) BroadcastAlert(alertMessage string) {
	messageData := map[string]string{
		"type":    "alert",
		"message": alertMessage,
	}
	
	jsonData, err := json.Marshal(messageData)
	if err != nil {
		log.Printf("Error marshaling alert message for WebSocket: %v", err)
		return
	}

	select {
	case h.alertBroadcast <- jsonData:
	default:
		log.Printf("Alert WebSocket broadcast channel full, dropping message")
	}
}

func (h *Hub) HandleWebSocket() fiber.Handler {
	return websocket.New(func(c *websocket.Conn) {
		defer func() {
			h.unregister <- c
		}()

		h.register <- c
		
		// Send welcome message to confirm connection
		welcomeMsg := map[string]string{"type": "welcome", "message": "WebSocket connected successfully"}
		if data, err := json.Marshal(welcomeMsg); err == nil {
			c.WriteMessage(websocket.TextMessage, data)
		}

		for {
			messageType, message, err := c.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				break
			}
			
			// Echo back any messages for testing
			log.Printf("Received WebSocket message: %s", string(message))
			if messageType == websocket.TextMessage {
				c.WriteMessage(websocket.TextMessage, message)
			}
		}
	})
}

func (h *Hub) HandleAlertsWebSocket() fiber.Handler {
	return websocket.New(func(c *websocket.Conn) {
		defer func() {
			h.alertUnregister <- c
		}()

		h.alertRegister <- c
		
		// Send welcome message to confirm connection
		welcomeMsg := map[string]string{"type": "welcome", "message": "Alert WebSocket connected successfully"}
		if data, err := json.Marshal(welcomeMsg); err == nil {
			c.WriteMessage(websocket.TextMessage, data)
		}

		for {
			messageType, message, err := c.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("Alert WebSocket error: %v", err)
				}
				break
			}
			
			// Echo back any messages for testing
			log.Printf("Received Alert WebSocket message: %s", string(message))
			if messageType == websocket.TextMessage {
				c.WriteMessage(websocket.TextMessage, message)
			}
		}
	})
}

func (h *Hub) UpgradeHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Log the upgrade attempt
		log.Printf("WebSocket upgrade attempt from %s", c.IP())
		log.Printf("Headers: %v", c.GetReqHeaders())
		
		if websocket.IsWebSocketUpgrade(c) {
			log.Printf("WebSocket upgrade headers valid")
			return c.Next()
		}
		log.Printf("WebSocket upgrade failed - missing required headers")
		return c.Status(http.StatusUpgradeRequired).SendString("WebSocket upgrade required")
	}
}
