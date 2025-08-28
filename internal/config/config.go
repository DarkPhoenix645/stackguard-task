package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
    Port                string
    TeamsClientID       string
    TeamsClientSecret   string
    TenantID            string
    SecurityChannelID   string
    MonitoringInterval  int
    MockMode            bool
    LogLevel            string
}

func Load() *Config {
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found or error loading .env file, using direct environment variables.")
    }

    cfg := &Config{}

    // --- Critical configuration (must be set, no defaults) ---
    // Using `getRequiredEnv` which will exit if the variable is not found
    cfg.TeamsClientID = getRequiredEnv("TEAMS_CLIENT_ID")
    cfg.TeamsClientSecret = getRequiredEnv("TEAMS_CLIENT_SECRET")
    cfg.TenantID = getRequiredEnv("TENANT_ID")
    cfg.SecurityChannelID = getRequiredEnv("SECURITY_CHANNEL_ID") 
    cfg.Port = getOptionalEnv("PORT", "8080")
    intervalStr := getOptionalEnv("MONITORING_INTERVAL", "30")

    var err error
    cfg.MonitoringInterval, err = strconv.Atoi(intervalStr)
    if err != nil {
        log.Fatalf("Configuration error: MONITORING_INTERVAL '%s' is not a valid integer: %v", intervalStr, err)
    }

    mockModeStr := getOptionalEnv("MOCK_MODE", "true")
    cfg.MockMode, err = strconv.ParseBool(mockModeStr)
    if err != nil {
        log.Fatalf("Configuration error: MOCK_MODE '%s' is not a valid boolean (true/false): %v", mockModeStr, err)
    }

    cfg.LogLevel = getOptionalEnv("LOG_LEVEL", "info")

    return cfg
}

func getRequiredEnv(key string) string {
    value := os.Getenv(key)
    if value == "" {
        log.Fatalf("Fatal: Required environment variable '%s' not set. Exiting.", key)
    }
    return value
}

func getOptionalEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}