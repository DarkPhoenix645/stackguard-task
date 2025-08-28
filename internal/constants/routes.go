package constants

// API Base Paths
const (
    APIBasePath = "/api"
    WebBasePath = "/"
)

// API Route Paths
const (
    // Health and monitoring routes
    HealthRoute = "/health"
    StatsRoute  = "/stats"
    
    // Detection routes
    DetectionsRoute           = "/detections"
    DetectionsByChannelRoute  = "/detections/channel/:channelId"
    DetectionsByStatusRoute   = "/detections/status/:status"
    DetectionStatusRoute      = "/detections/:id/status"
    ClearDetectionsRoute      = "/detections/clear"
    
    // Webhook routes
    TeamsWebhookRoute         = "/webhook/teams"
    TestDetectionRoute        = "/test/detect"
    
    // WebSocket routes
    WebSocketRoute            = "/ws"
    AlertsWebSocketRoute      = "/ws/messages"
    
    // Static and SPA routes
    StaticFilesPath          = "./web/static"
    SPACatchAllRoute         = "/*"
    SPAIndexFile            = "./web/static/index.html"
)