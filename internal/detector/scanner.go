package detector

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"
	"time"

	"stackguard-task/internal/models"
)

type SecretScanner struct {
    patterns []SecretPattern
}

type SecretPattern struct {
    Name        string
    Pattern     *regexp.Regexp
    Severity    string
    Confidence  float64
    Description string
}

func NewSecretScanner() *SecretScanner {
    return &SecretScanner{
        patterns: getSecretPatterns(),
    }
}

func (s *SecretScanner) ScanMessage(msg models.TeamsMessage) []models.SecretDetection {
    var detections []models.SecretDetection
    content := msg.Body.Content
    
    // Handle large messages (>5000 chars)
    originalContent := content
    if len(content) > 5000 {
        content = content[:5000]
    }
    
    for _, pattern := range s.patterns {
        matches := pattern.Pattern.FindAllString(content, -1)
        
        for _, match := range matches {
            // Skip false positives
            if s.isFalsePositive(match, originalContent) {
                continue
            }
            
            detection := models.SecretDetection{
                ID:          generateDetectionID(msg.ID, match),
                MessageID:   msg.ID,
                ChannelID:   msg.ChannelID,
                TeamID:      msg.TeamID,
                UserID:      msg.From.User.ID,
                UserName:    msg.From.User.DisplayName,
                SecretType:  pattern.Name,
                MaskedValue: maskSecret(match),
                FullValue:   match, // Store for internal use only
                Confidence:  pattern.Confidence,
                Context:     extractContext(originalContent, match),
                DetectedAt:  time.Now(),
                Severity:    pattern.Severity,
                Status:      "new",
            }
            
            detections = append(detections, detection)
        }
    }
    
    return detections
}

func (s *SecretScanner) isFalsePositive(match, content string) bool {
    lowerContent := strings.ToLower(content)
    lowerMatch := strings.ToLower(match)
    
    // Common false positive patterns
    falsePositives := []string{
        "test", "example", "demo", "sample", "placeholder",
        "fake", "mock", "dummy", "template", "documentation",
        "akiaxxxxxxxxtest", "akiaiosfodnn7example", "your-api-key",
        "replace-with", "insert-your", "add-your",
    }
    
    for _, fp := range falsePositives {
        if strings.Contains(lowerContent, fp) || strings.Contains(lowerMatch, fp) {
            return true
        }
    }
    
    return false
}

func maskSecret(secret string) string {
    if len(secret) <= 8 {
        return strings.Repeat("*", len(secret))
    }
    
    // Show first 4 and last 4 characters
    return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

func extractContext(content, match string) string {
    index := strings.Index(content, match)
    if index == -1 {
        return ""
    }
    
    start := index - 50
    if start < 0 {
        start = 0
    }
    
    end := index + len(match) + 50
    if end > len(content) {
        end = len(content)
    }
    
    context := content[start:end]
    // Replace the actual secret with masked version in context
    context = strings.ReplaceAll(context, match, maskSecret(match))
    
    return strings.TrimSpace(context)
}

func generateDetectionID(messageID, secret string) string {
    hash := md5.Sum([]byte(messageID + secret))
    return fmt.Sprintf("det_%x", hash)[:16]
}

func getSecretPatterns() []SecretPattern {
    return []SecretPattern{
        {
            Name:        "AWS Access Key",
            Pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
            Severity:    "HIGH",
            Confidence:  0.95,
            Description: "AWS Access Key ID detected",
        },
        {
            Name:        "AWS Secret Key",
            Pattern:     regexp.MustCompile(`[A-Za-z0-9/+=]{40}`),
            Severity:    "HIGH",
            Confidence:  0.7,
            Description: "Potential AWS Secret Access Key",
        },
        {
            Name:        "GitHub Token",
            Pattern:     regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
            Severity:    "HIGH",
            Confidence:  0.98,
            Description: "GitHub Personal Access Token",
        },
        {
            Name:        "JWT Token",
            Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
            Severity:    "MEDIUM",
            Confidence:  0.8,
            Description: "JSON Web Token detected",
        },
        {
            Name:        "API Key Generic",
            Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)["\s]*[:=]["\s]*[A-Za-z0-9]{20,}`),
            Severity:    "MEDIUM",
            Confidence:  0.6,
            Description: "Generic API key pattern",
        },
        {
            Name:        "Database URL",
            Pattern:     regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis)://[^\s]+`),
            Severity:    "HIGH",
            Confidence:  0.9,
            Description: "Database connection string",
        },
        {
            Name:        "Private Key",
            Pattern:     regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`),
            Severity:    "CRITICAL",
            Confidence:  0.99,
            Description: "Private key detected",
        },
        {
            Name:        "Slack Token",
            Pattern:     regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
            Severity:    "HIGH",
            Confidence:  0.95,
            Description: "Slack API token",
        },
        {
            Name:        "Google API Key",
            Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
            Severity:    "HIGH",
            Confidence:  0.9,
            Description: "Google API key",
        },
    }
}