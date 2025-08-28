package constants
const (
    // Alert message template
    AlertMessageTemplate = `%s **SECURITY ALERT** %s

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
		*Detection ID: %s*`

    // Severity emojis
    SeverityCritical = "🚨"
    SeverityHigh     = "⚠️"
    SeverityMedium   = "⚡"
    SeverityLow      = "ℹ️"
    SeverityDefault  = "🔍"
    
    // Alert types
    AlertTypeSecretDetected = "SECRET_DETECTED"
    AlertTypeHighRisk       = "HIGH_RISK_SECRET"
    AlertTypeCriticalRisk   = "CRITICAL_RISK_SECRET"
    
    // Status messages
    StatusNew          = "new"
    StatusAcknowledged = "acknowledged"
    StatusResolved     = "resolved"
    StatusFalsePositive = "false_positive"
    
    // API Response messages
    MsgDetectionUpdated     = "Detection status updated successfully"
    MsgSecretDetectionTest  = "Secret detection test completed"
    MsgMessageProcessed     = "Message processed successfully"
    MsgHealthy              = "Service is healthy"
    
    // Error messages
    ErrInvalidRequestBody    = "Invalid request body"
    ErrChannelIDRequired     = "Channel ID is required"
    ErrDetectionIDRequired   = "Detection ID is required"
    ErrTextRequired          = "Text is required"
    ErrInvalidStatus         = "Invalid status. Must be: new, acknowledged, resolved, or false_positive"
    ErrDetectionNotFound     = "Detection not found"
    ErrInvalidWebhookPayload = "Invalid webhook payload"
)

// GetSeverityEmoji returns the appropriate emoji for a severity level
func GetSeverityEmoji(severity string) string {
    switch severity {
    case "CRITICAL":
        return SeverityCritical
    case "HIGH":
        return SeverityHigh
    case "MEDIUM":
        return SeverityMedium
    case "LOW":
        return SeverityLow
    default:
        return SeverityDefault
    }
}

func GetValidStatuses() []string {
    return []string{StatusNew, StatusAcknowledged, StatusResolved, StatusFalsePositive}
}

func IsValidStatus(status string) bool {
    validStatuses := GetValidStatuses()
    for _, validStatus := range validStatuses {
        if status == validStatus {
            return true
        }
    }
    return false
}