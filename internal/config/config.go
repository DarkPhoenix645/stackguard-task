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
    // Load .env file
    if err := godotenv.Load(); err != nil {
        log.Println("No .env file found, using environment variables")
    }
    
    mockMode, _ := strconv.ParseBool(getEnv("MOCK_MODE", "true"))
    interval, _ := strconv.Atoi(getEnv("MONITORING_INTERVAL", "30"))
    
    return &Config{
        Port:                getEnv("PORT", "8080"),
        TeamsClientID:       getEnv("TEAMS_CLIENT_ID", "mock-client-id"),
        TeamsClientSecret:   getEnv("TEAMS_CLIENT_SECRET", "mock-client-secret"),
        TenantID:           getEnv("TENANT_ID", "mock-tenant-id"),
        SecurityChannelID:   getEnv("SECURITY_CHANNEL_ID", "security-alerts"),
        MonitoringInterval:  interval,
        MockMode:           mockMode,
        LogLevel:           getEnv("LOG_LEVEL", "info"),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}