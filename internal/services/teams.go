package services

import (
	"log"

	"stackguard-task/internal/config"
	"stackguard-task/internal/detector"
	"stackguard-task/internal/models"
	"stackguard-task/internal/storage"
)

type TeamsService struct {
    config  *config.Config
    scanner *detector.SecretScanner
    store   storage.Store
}

func NewTeamsService(cfg *config.Config, store storage.Store) *TeamsService {
    return &TeamsService{
        config:  cfg,
        scanner: detector.NewSecretScanner(),
        store:   store,
    }
}

func (ts *TeamsService) ProcessMessage(message models.TeamsMessage) ([]models.SecretDetection, error) {
    // Scan message for secrets
    detections := ts.scanner.ScanMessage(message)
    
    // Save detections to storage
    for _, detection := range detections {
        if err := ts.store.SaveDetection(detection); err != nil {
            log.Printf("Error saving detection: %v", err)
            continue
        }
        
        log.Printf("Secret detected: %s in channel %s by user %s", 
            detection.SecretType, detection.ChannelID, detection.UserName)
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