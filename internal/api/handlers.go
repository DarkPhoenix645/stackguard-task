package api

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"stackguard-task/internal/models"
	"stackguard-task/internal/services"
)

type Handler struct {
    teamsService *services.TeamsService
    alertService *services.AlertService
}

func NewHandler(teamsService *services.TeamsService, alertService *services.AlertService) *Handler {
    return &Handler{
        teamsService: teamsService,
        alertService: alertService,
    }
}

// Health check endpoint
func (h *Handler) HealthCheck(c *fiber.Ctx) error {
    return c.JSON(models.APIResponse{
        Success: true,
        Data: fiber.Map{
            "status":    "healthy",
            "service":   "teams-connector",
            "timestamp": time.Now(),
        },
    })
}

// Get dashboard statistics
func (h *Handler) GetStats(c *fiber.Ctx) error {
    stats, err := h.teamsService.GetStats()
    if err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Data:    stats,
    })
}

// Get detections with optional limit
func (h *Handler) GetDetections(c *fiber.Ctx) error {
    limitStr := c.Query("limit", "50")
    limit, err := strconv.Atoi(limitStr)
    if err != nil {
        limit = 50
    }
    
    detections, err := h.teamsService.GetDetections(limit)
    if err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Data:    detections,
    })
}

// Get detections by channel
func (h *Handler) GetDetectionsByChannel(c *fiber.Ctx) error {
    channelID := c.Params("channelId")
    if channelID == "" {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Channel ID is required",
        })
    }
    
    detections, err := h.teamsService.GetDetectionsByChannel(channelID)
    if err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Data:    detections,
    })
}

// Update detection status
func (h *Handler) UpdateDetectionStatus(c *fiber.Ctx) error {
    id := c.Params("id")
    if id == "" {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Detection ID is required",
        })
    }
    
    var request struct {
        Status string `json:"status"`
    }
    
    if err := c.BodyParser(&request); err != nil {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Invalid request body",
        })
    }
    
    // Validate status
    validStatuses := map[string]bool{
        "new":          true,
        "acknowledged": true,
        "resolved":     true,
    }
    
    if !validStatuses[request.Status] {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Invalid status. Must be: new, acknowledged, or resolved",
        })
    }
    
    if err := h.teamsService.UpdateDetectionStatus(id, request.Status); err != nil {
        return c.Status(404).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Message: "Detection status updated successfully",
    })
}

// Mock Teams webhook endpoint - this is what Postman will call
func (h *Handler) TeamsWebhook(c *fiber.Ctx) error {
    var payload models.WebhookPayload
    
    if err := c.BodyParser(&payload); err != nil {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Invalid webhook payload",
        })
    }
    
    // Set default values if not provided
    if payload.Message.ID == "" {
        payload.Message.ID = uuid.New().String()
    }
    if payload.Message.CreatedAt.IsZero() {
        payload.Message.CreatedAt = time.Now()
    }
    if payload.Timestamp.IsZero() {
        payload.Timestamp = time.Now()
    }
    
    // Process the message
    detections, err := h.teamsService.ProcessMessage(payload.Message)
    if err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    // Send alerts for each detection
    for _, detection := range detections {
        if err := h.alertService.SendAlert(detection, payload.Message); err != nil {
            // Log error but don't fail the request
            c.Locals("alertError", err.Error())
        }
    }
    
    response := fiber.Map{
        "processed":       true,
        "detectionsFound": len(detections),
        "detections":      detections,
    }
    
    if alertError := c.Locals("alertError"); alertError != nil {
        response["alertError"] = alertError
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Data:    response,
        Message: "Message processed successfully",
    })
}

// Test endpoint for manual secret detection
func (h *Handler) TestSecretDetection(c *fiber.Ctx) error {
    var request struct {
        Text      string `json:"text"`
        ChannelID string `json:"channelId"`
        UserName  string `json:"userName"`
    }
    
    if err := c.BodyParser(&request); err != nil {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Invalid request body",
        })
    }
    
    if request.Text == "" {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Text is required",
        })
    }
    
    // Create a mock message
    mockMessage := models.TeamsMessage{
        ID:        uuid.New().String(),
        CreatedAt: time.Now(),
        ChannelID: request.ChannelID,
        TeamID:    "test-team",
        Body: models.MessageBody{
            ContentType: "text",
            Content:     request.Text,
        },
        From: models.MessageFrom{
            User: struct {
                ID          string `json:"id"`
                DisplayName string `json:"displayName"`
                UserType    string `json:"userPrincipalName"`
            }{
                ID:          "test-user-id",
                DisplayName: request.UserName,
                UserType:    "user",
            },
        },
    }
    
    // Process the message
    detections, err := h.teamsService.ProcessMessage(mockMessage)
    if err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Data: fiber.Map{
            "message":         mockMessage,
            "detectionsFound": len(detections),
            "detections":      detections,
        },
        Message: "Secret detection test completed",
    })
}