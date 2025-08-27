package models

import (
	"time"
)

type TeamsMessage struct {
	ID          string      `json:"id"`
	CreatedAt   time.Time   `json:"createdDateTime"`
	From        MessageFrom `json:"from"`
	Body        MessageBody `json:"body"`
	ChannelID   string      `json:"channelId"`
	TeamID      string      `json:"teamId"`
	WebURL      string      `json:"webUrl"`
}

type MessageFrom struct {
	User struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		UserType    string `json:"userPrincipalName"`
	} `json:"user"`
}

type MessageBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type SecretDetection struct {
	ID          string    `json:"id"`
	MessageID   string    `json:"messageId"`
	ChannelID   string    `json:"channelId"`
	TeamID      string    `json:"teamId"`
	UserID      string    `json:"userId"`
	UserName    string    `json:"userName"`
	SecretType  string    `json:"secretType"`
	MaskedValue string    `json:"maskedValue"`
	FullValue   string    `json:"-"` // Never serialize this
	Confidence  float64   `json:"confidence"`
	Context     string    `json:"context"`
	DetectedAt  time.Time `json:"detectedAt"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"` // "new", "acknowledged", "resolved"
}

type AlertRequest struct {
	Detection   SecretDetection `json:"detection"`
	Message     TeamsMessage    `json:"message"`
	AlertType   string          `json:"alertType"`
}

type DashboardStats struct {
	TotalDetections     int               `json:"totalDetections"`
	DetectionsByType    map[string]int    `json:"detectionsByType"`
	DetectionsBySeverity map[string]int   `json:"detectionsBySeverity"`
	RecentDetections    []SecretDetection `json:"recentDetections"`
	ChannelStats        map[string]int    `json:"channelStats"`
}

type WebhookPayload struct {
	Type         string       `json:"type"`
	Message      TeamsMessage `json:"message"`
	ChannelID    string       `json:"channelId"`
	TeamID       string       `json:"teamId"`
	Timestamp    time.Time    `json:"timestamp"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}