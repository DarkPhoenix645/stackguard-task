package services

import (
	"log"

	"stackguard-task/internal/config"
	"stackguard-task/internal/detector"
	"stackguard-task/internal/models"
	"stackguard-task/internal/storage"
)

type TeamsService struct {
    config       *config.Config
    scanner      *detector.SecretScanner
    store        storage.Store
    alertService *AlertService
}

func NewTeamsService(cfg *config.Config, store storage.Store, alertService *AlertService) *TeamsService {
    return &TeamsService{
        config:       cfg,
        scanner:      detector.NewSecretScanner(),
        store:        store,
        alertService: alertService,
    }
}

func (ts *TeamsService) ProcessMessage(message models.TeamsMessage) ([]models.SecretDetection, error) {
    // Scan message for secrets (returns deduplicated, sorted by confidence)
    detections := ts.scanner.ScanMessage(message)
    
    // Save only the highest confidence detection to storage to avoid duplicates
    // but return all detections for API responses
    if len(detections) > 0 {
        highestConfidenceDetection := detections[0] // Already sorted by confidence
        if err := ts.store.SaveDetection(highestConfidenceDetection); err != nil {
            log.Printf("Error saving detection: %v", err)
        } else {
            log.Printf("Secret detected: %s in channel %s by user %s (confidence: %.2f)", 
                highestConfidenceDetection.SecretType, highestConfidenceDetection.ChannelID, 
                highestConfidenceDetection.UserName, highestConfidenceDetection.Confidence)
            
            // Send alert via WebSocket
            if ts.alertService != nil {
                if err := ts.alertService.SendAlert(highestConfidenceDetection); err != nil {
                    log.Printf("Error sending alert: %v", err)
                }
            }
        }
    }
    
    return detections, nil
}

func (ts *TeamsService) GetDetections(limit int) ([]models.SecretDetection, error) {
    return ts.store.GetDetections(limit)
}

func (ts *TeamsService) GetDetectionsByChannel(channelID string) ([]models.SecretDetection, error) {
    return ts.store.GetDetectionsByChannel(channelID)
}

func (ts *TeamsService) GetStats() (models.DashboardStats, error) {
    return ts.store.GetStats()
}

func (ts *TeamsService) UpdateDetectionStatus(id, status string) error {
    return ts.store.UpdateDetectionStatus(id, status)
}

func (ts *TeamsService) ClearAllDetections() error {
    return ts.store.ClearAllDetections()
}

func (ts *TeamsService) GetDetectionsByStatus(status string) ([]models.SecretDetection, error) {
    return ts.store.GetDetectionsByStatus(status)
}