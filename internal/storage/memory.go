package storage

import (
	"fmt"
	"sort"
	"sync"

	"stackguard-task/internal/models"
)

type Store interface {
    SaveDetection(detection models.SecretDetection) error
    GetDetections(limit int) ([]models.SecretDetection, error)
    GetDetectionsByChannel(channelID string) ([]models.SecretDetection, error)
    GetDetectionsByType(secretType string) ([]models.SecretDetection, error)
    GetStats() (models.DashboardStats, error)
    UpdateDetectionStatus(id, status string) error
    GetDetectionByID(id string) (*models.SecretDetection, error)
    ClearAllDetections() error
    GetDetectionsByStatus(status string) ([]models.SecretDetection, error)
}

type MemoryStore struct {
    detections map[string]models.SecretDetection
    mutex      sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
    return &MemoryStore{
        detections: make(map[string]models.SecretDetection),
    }
}

func (ms *MemoryStore) SaveDetection(detection models.SecretDetection) error {
    ms.mutex.Lock()
    defer ms.mutex.Unlock()
    
    ms.detections[detection.ID] = detection
    return nil
}

func (ms *MemoryStore) GetDetections(limit int) ([]models.SecretDetection, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    
    var detections []models.SecretDetection
    for _, detection := range ms.detections {
        detections = append(detections, detection)
    }
    
    // Sort by detection time (newest first)
    sort.Slice(detections, func(i, j int) bool {
        return detections[i].DetectedAt.After(detections[j].DetectedAt)
    })
    
    if limit > 0 && len(detections) > limit {
        detections = detections[:limit]
    }
    
    return detections, nil
}

func (ms *MemoryStore) GetDetectionsByChannel(channelID string) ([]models.SecretDetection, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    
    var detections []models.SecretDetection
    for _, detection := range ms.detections {
        if detection.ChannelID == channelID {
            detections = append(detections, detection)
        }
    }
    
    return detections, nil
}

func (ms *MemoryStore) GetDetectionsByType(secretType string) ([]models.SecretDetection, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    
    var detections []models.SecretDetection
    for _, detection := range ms.detections {
        if detection.SecretType == secretType {
            detections = append(detections, detection)
        }
    }
    
    return detections, nil
}

func (ms *MemoryStore) GetStats() (models.DashboardStats, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    
    stats := models.DashboardStats{
        DetectionsByType:     make(map[string]int),
        DetectionsBySeverity: make(map[string]int),
        ChannelStats:         make(map[string]int),
    }
    
    var recentDetections []models.SecretDetection
    
    for _, detection := range ms.detections {
        stats.TotalDetections++
        stats.DetectionsByType[detection.SecretType]++
        stats.DetectionsBySeverity[detection.Severity]++
        stats.ChannelStats[detection.ChannelID]++
        
        recentDetections = append(recentDetections, detection)
    }
    
    // Sort and limit recent detections
    sort.Slice(recentDetections, func(i, j int) bool {
        return recentDetections[i].DetectedAt.After(recentDetections[j].DetectedAt)
    })
    
    if len(recentDetections) > 10 {
        recentDetections = recentDetections[:10]
    }
    
    stats.RecentDetections = recentDetections
    
    return stats, nil
}

func (ms *MemoryStore) UpdateDetectionStatus(id, status string) error {
    ms.mutex.Lock()
    defer ms.mutex.Unlock()
    
    if detection, exists := ms.detections[id]; exists {
        detection.Status = status
        ms.detections[id] = detection
        return nil
    }
    
    return fmt.Errorf("detection not found: %s", id)
}

func (ms *MemoryStore) GetDetectionByID(id string) (*models.SecretDetection, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    
    if detection, exists := ms.detections[id]; exists {
        return &detection, nil
    }
    
    return nil, fmt.Errorf("detection not found: %s", id)
}

// ClearAllDetections removes all detections from memory store
func (ms *MemoryStore) ClearAllDetections() error {
    ms.mutex.Lock()
    defer ms.mutex.Unlock()
    
    ms.detections = make(map[string]models.SecretDetection)
    return nil
}

// GetDetectionsByStatus returns detections filtered by status
func (ms *MemoryStore) GetDetectionsByStatus(status string) ([]models.SecretDetection, error) {
    ms.mutex.RLock()
    defer ms.mutex.RUnlock()
    
    var detections []models.SecretDetection
    for _, detection := range ms.detections {
        if detection.Status == status {
            detections = append(detections, detection)
        }
    }
    
    // Sort by detection time (newest first)
    sort.Slice(detections, func(i, j int) bool {
        return detections[i].DetectedAt.After(detections[j].DetectedAt)
    })
    
    return detections, nil
}