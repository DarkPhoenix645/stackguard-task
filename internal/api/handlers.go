package api

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"stackguard-task/internal/constants"
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

func (h *Handler) UpdateDetectionStatus(c *fiber.Ctx) error {
    id := c.Params("id")
    if id == "" {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   constants.ErrDetectionIDRequired,
        })
    }
    
    var request struct {
        Status string `json:"status"`
    }
    
    if err := c.BodyParser(&request); err != nil {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   constants.ErrInvalidRequestBody,
        })
    }
    
    // Validate status using constants
    if !constants.IsValidStatus(request.Status) {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   constants.ErrInvalidStatus,
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
        Message: constants.MsgDetectionUpdated,
    })
}

func (h *Handler) TeamsWebhook(c *fiber.Ctx) error {
    var payload models.WebhookPayload
    
    if err := c.BodyParser(&payload); err != nil {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Invalid webhook payload",
        })
    }
    
    if payload.Message.ID == "" {
        payload.Message.ID = uuid.New().String()
    }
    if payload.Message.CreatedAt.IsZero() {
        payload.Message.CreatedAt = time.Now()
    }
    if payload.Timestamp.IsZero() {
        payload.Timestamp = time.Now()
    }
    
    detections, err := h.teamsService.ProcessMessage(payload.Message)
    if err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    for _, detection := range detections {
        if err := h.alertService.SendAlert(detection); err != nil {
            // Log error but don't fail the entire request
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

func (h *Handler) ClearDetections(c *fiber.Ctx) error {
    if err := h.teamsService.ClearAllDetections(); err != nil {
        return c.Status(500).JSON(models.APIResponse{
            Success: false,
            Error:   err.Error(),
        })
    }
    
    return c.JSON(models.APIResponse{
        Success: true,
        Message: "All detections cleared successfully",
    })
}

func (h *Handler) GetDetectionsByStatus(c *fiber.Ctx) error {
    status := c.Params("status")
    if status == "" {
        return c.Status(400).JSON(models.APIResponse{
            Success: false,
            Error:   "Status parameter is required",
        })
    }
    
    detections, err := h.teamsService.GetDetectionsByStatus(status)
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