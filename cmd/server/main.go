package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"stackguard-task/internal/api"
	"stackguard-task/internal/config"
	"stackguard-task/internal/constants"
	"stackguard-task/internal/services"
	"stackguard-task/internal/storage"
)

func main() {
    // Initialize (load config, setup memory, services and Fiber app)
    cfg := config.Load()
    
	store := storage.NewMemoryStore()

    teamsService := services.NewTeamsService(cfg, store)
    alertService := services.NewAlertService(cfg)
    
    app := fiber.New(fiber.Config{
        AppName: "Teams Security Connector",
        ErrorHandler: func(c *fiber.Ctx, err error) error {
            code := fiber.StatusInternalServerError
            if e, ok := err.(*fiber.Error); ok {
                code = e.Code
            }
            
            return c.Status(code).JSON(fiber.Map{
                "success": false,
                "error":   err.Error(),
            })
        },
    })
    
    // Middleware
    app.Use(recover.New())
    app.Use(logger.New(logger.Config{
        Format: "[${time}] ${status} - ${method} ${path} - ${latency}\n",
    }))
    app.Use(cors.New(cors.Config{
        AllowOrigins: "*",
        AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
        AllowHeaders: "Origin,Content-Type,Accept,Authorization",
    }))
    
    // Initialize handlers
    handler := api.NewHandler(teamsService, alertService)
    setupRoutes(app, handler)
    
    // Start server
    go func() {
        log.Printf("Server starting on port %s", cfg.Port)
        log.Printf("Dashboard: http://localhost:%s", cfg.Port)
        log.Printf("API Health: http://localhost:%s/api/health", cfg.Port)
        log.Printf("Webhook: http://localhost:%s/api/webhook/teams", cfg.Port)
        
        if err := app.Listen(":" + cfg.Port); err != nil {
            log.Fatalf("Server failed to start: %v", err)
        }
    }()
    
    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    log.Println("Shutting down server...")
    if err := app.Shutdown(); err != nil {
        log.Fatalf("Server forced to shutdown: %v", err)
    }
    
    log.Println("Server exited")
}

func setupRoutes(app *fiber.App, handler *api.Handler) {
    // API routes
    apiGroup := app.Group(constants.APIBasePath)
    
    // Health and monitoring
    apiGroup.Get(constants.HealthRoute, handler.HealthCheck)
    apiGroup.Get(constants.StatsRoute, handler.GetStats)
    
    // Detections
    apiGroup.Get(constants.DetectionsRoute, handler.GetDetections)
    apiGroup.Get(constants.DetectionsByChannelRoute, handler.GetDetectionsByChannel)
    apiGroup.Get(constants.DetectionsByStatusRoute, handler.GetDetectionsByStatus)
    apiGroup.Put(constants.DetectionStatusRoute, handler.UpdateDetectionStatus)
    apiGroup.Delete(constants.ClearDetectionsRoute, handler.ClearDetections)
    
    // Webhook endpoints
    apiGroup.Post(constants.TeamsWebhookRoute, handler.TeamsWebhook)
    apiGroup.Post(constants.TestDetectionRoute, handler.TestSecretDetection)
    
    // Static files and dashboard
    app.Static(constants.WebBasePath, constants.StaticFilesPath)
    
    // Catch-all for SPA routing
    app.Get(constants.SPACatchAllRoute, func(c *fiber.Ctx) error {
        return c.SendFile(constants.SPAIndexFile)
    })
}