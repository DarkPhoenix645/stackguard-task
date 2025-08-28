package services

import (
	"fmt"
	"log"

	"stackguard-task/internal/config"
	"stackguard-task/internal/constants"
	"stackguard-task/internal/models"
)

type AlertService struct {
    config *config.Config
    wsHub  WebSocketHub
}

type WebSocketHub interface {
    BroadcastDetection(detection models.SecretDetection)
    BroadcastAlert(alertMessage string)
}

func NewAlertService(cfg *config.Config, wsHub WebSocketHub) *AlertService {
    return &AlertService{
        config: cfg,
        wsHub:  wsHub,
    }
}

func (as *AlertService) SendAlert(detection models.SecretDetection) error {
    alertMessage := as.formatAlertMessage(detection)
    
    // Broadcast to WebSocket clients
    if as.wsHub != nil {
        as.wsHub.BroadcastDetection(detection)
        as.wsHub.BroadcastAlert(alertMessage)
    }
    
    // In mock mode, just log the alert
    if as.config.MockMode {
        log.Printf("MOCK ALERT: %s", alertMessage)
        return nil
    }
    
    // In production, this would send to Teams security channel
    // Implementation would use Microsoft Graph API
    
    return nil
}

func (as *AlertService) formatAlertMessage(detection models.SecretDetection) string {
    emoji := constants.GetSeverityEmoji(detection.Severity)
    
    return fmt.Sprintf(constants.AlertMessageTemplate,
        emoji, emoji,
        detection.SecretType,
        detection.Severity,
        detection.Confidence*100,
        detection.ChannelID,
        detection.UserName,
        detection.DetectedAt.Format("2006-01-02 15:04:05"),
        detection.MaskedValue,
        detection.Context,
        detection.ID,
    )
}

// GetAlertType determines the alert type based on detection severity and confidence
func (as *AlertService) GetAlertType(detection models.SecretDetection) string {
    if detection.Severity == "CRITICAL" || (detection.Severity == "HIGH" && detection.Confidence > 0.9) {
        return constants.AlertTypeCriticalRisk
    } else if detection.Severity == "HIGH" || detection.Confidence > 0.8 {
        return constants.AlertTypeHighRisk
    }
    return constants.AlertTypeSecretDetected
}