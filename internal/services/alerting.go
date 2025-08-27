package services

import (
	"fmt"
	"log"

	"stackguard-task/internal/config"
	"stackguard-task/internal/models"
)

type AlertService struct {
    config *config.Config
}

func NewAlertService(cfg *config.Config) *AlertService {
    return &AlertService{
        config: cfg,
    }
}

func (as *AlertService) SendAlert(detection models.SecretDetection, message models.TeamsMessage) error {
    // Create alert message
    alertMessage := as.formatAlertMessage(detection, message)
    
    // In mock mode, just log the alert
    if as.config.MockMode {
        log.Printf("MOCK ALERT: %s", alertMessage)
        return nil
    }
    
    // In production, this would send to Teams security channel
    // Implementation would use Microsoft Graph API
    
    return nil
}

func (as *AlertService) formatAlertMessage(detection models.SecretDetection, message models.TeamsMessage) string {
    severityEmoji := map[string]string{
        "CRITICAL": "🚨",
        "HIGH":     "⚠️",
        "MEDIUM":   "⚡",
        "LOW":      "ℹ️",
    }
    
    emoji := severityEmoji[detection.Severity]
    if emoji == "" {
        emoji = "🔍"
    }
    
    return fmt.Sprintf(`%s **SECURITY ALERT** %s

**Secret Type:** %s
**Severity:** %s
**Confidence:** %.0f%%
**Channel:** %s
**User:** %s
**Detected:** %s

**Masked Value:** %s

**Context:**
%s

**Action Required:** Please review and revoke this credential immediately if it's legitimate.

---
*Detection ID: %s*`,
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