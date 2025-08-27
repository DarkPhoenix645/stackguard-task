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
    
    // Static and SPA routes
    StaticFilesPath          = "./web/static"
    SPACatchAllRoute         = "/*"
    SPAIndexFile            = "./web/static/index.html"
)

// Full API Paths (for documentation and testing)
const (
    FullHealthRoute              = APIBasePath + HealthRoute
    FullStatsRoute               = APIBasePath + StatsRoute
    FullDetectionsRoute          = APIBasePath + DetectionsRoute
    FullDetectionsByChannelRoute = APIBasePath + DetectionsByChannelRoute
    FullDetectionStatusRoute     = APIBasePath + DetectionStatusRoute
    FullTeamsWebhookRoute        = APIBasePath + TeamsWebhookRoute
    FullTestDetectionRoute       = APIBasePath + TestDetectionRoute
)

// HTTP Methods
const (
    MethodGET    = "GET"
    MethodPOST   = "POST"
    MethodPUT    = "PUT"
    MethodDELETE = "DELETE"
    MethodPATCH  = "PATCH"
)

// Route Parameters
const (
    ParamChannelID   = "channelId"
    ParamDetectionID = "id"
)

// Query Parameters
const (
    QueryLimit  = "limit"
    QueryOffset = "offset"
    QueryStatus = "status"
    QueryType   = "type"
)