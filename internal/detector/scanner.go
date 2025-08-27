package detector

import (
	"crypto/md5"
	"fmt"
	"html"
	"regexp"
	"sort"
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
    
    // Preprocess content to handle newlines and special characters
    content = s.preprocessContent(content)
    
    // TODO: Handle large messages (>5000 chars)
    originalContent := content
    if len(content) > 5000 {
        content = content[:5000]
    }
    
    confidenceCalc := NewConfidenceCalculator()
    
    for _, pattern := range s.patterns {
        matches := pattern.Pattern.FindAllString(content, -1)
        
        for _, match := range matches {
            if s.isFalsePositive(match, originalContent) {
                continue
            }
            
            context := extractContext(originalContent, match)
            confidence := confidenceCalc.CalculateConfidence(match, context, pattern.Name)
            
            // Apply lower bound for confidence
            if confidence < 0.3 {
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
                FullValue:   match,
                Confidence:  confidence,
                Context:     context,
                DetectedAt:  time.Now(),
                Severity:    pattern.Severity,
                Status:      "new",
            }
            
            detections = append(detections, detection)
        }
    }
    
    // Sort detections by confidence (highest first)
    sort.Slice(detections, func(i, j int) bool {
        return detections[i].Confidence > detections[j].Confidence
    })
    
    // Deduplicate overlapping detections - keep only the highest confidence one
    detections = s.deduplicateDetections(detections)
    
    return detections
}

func (s *SecretScanner) preprocessContent(content string) string {
    // Decode HTML entities (Teams messages might contain &lt;, &gt;, etc.)
    content = html.UnescapeString(content)
    
    // Convert JSON-escaped newlines to actual newlines
    content = strings.ReplaceAll(content, "\\n", "\n")
    content = strings.ReplaceAll(content, "\\r", "\r")
    content = strings.ReplaceAll(content, "\\t", "\t")
    
    // Normalize different types of whitespace to spaces for pattern matching
    // This helps catch secrets that might be split with unusual whitespace
    return regexp.MustCompile(`\s+`).ReplaceAllString(content, " ")
}

func (s *SecretScanner) deduplicateDetections(detections []models.SecretDetection) []models.SecretDetection {
    if len(detections) <= 1 {
        return detections
    }
    
    var deduplicated []models.SecretDetection
    used := make(map[int]bool)
    
    for i, detection := range detections {
        if used[i] {
            continue
        }
        
        // Check if this detection overlaps with any higher confidence detection
        isOverlapping := false
        for j := 0; j < i; j++ {
            if used[j] {
                continue
            }
            
            other := detections[j]
            if s.detectionsOverlap(detection, other) {
                isOverlapping = true
                break
            }
        }
        
        if !isOverlapping {
            deduplicated = append(deduplicated, detection)
            used[i] = true
            
            // Mark any lower confidence overlapping detections as used
            for j := i + 1; j < len(detections); j++ {
                if s.detectionsOverlap(detection, detections[j]) {
                    used[j] = true
                }
            }
        }
    }
    
    return deduplicated
}

// detectionsOverlap checks if two detections are for the same or overlapping secrets
func (s *SecretScanner) detectionsOverlap(d1, d2 models.SecretDetection) bool {
    // Same exact match
    if d1.FullValue == d2.FullValue {
        return true
    }
    
    // One secret contains the other (e.g., private key contains base64 chunks)
    if strings.Contains(d1.FullValue, d2.FullValue) || strings.Contains(d2.FullValue, d1.FullValue) {
        return true
    }
    
    // Check if they have significant overlap (>80% of the shorter string)
    shorter, longer := d1.FullValue, d2.FullValue
    if len(d2.FullValue) < len(d1.FullValue) {
        shorter, longer = d2.FullValue, d1.FullValue
    }
    
    // Only check overlap for reasonably long secrets
    if len(shorter) > 10 {
        overlapThreshold := int(float64(len(shorter)) * 0.8)
        if strings.Contains(longer, shorter[:overlapThreshold]) {
            return true
        }
    }
    
    return false
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
            Description: "AWS Access Key ID detected",
        },
        {
            Name:        "AWS Secret Key",
            Pattern:     regexp.MustCompile(`[A-Za-z0-9/+=]{40}`),
            Severity:    "HIGH",
            Description: "Potential AWS Secret Access Key",
        },
        {
            Name:        "GitHub Token",
            Pattern:     regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
            Severity:    "HIGH",
            Description: "GitHub Personal Access Token",
        },
        {
            Name:        "JWT Token",
            Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
            Severity:    "MEDIUM",
            Description: "JSON Web Token detected",
        },
        {
            Name:        "API Key Generic",
            Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key)["\s]*[:=]["\s]*[A-Za-z0-9]{20,}`),
            Severity:    "MEDIUM",
            Description: "Generic API key pattern",
        },
        {
            Name:        "Database URL",
            Pattern:     regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis)://[^\s]+`),
            Severity:    "HIGH",
            Description: "Database connection string",
        },
        {
            Name:        "Private Key",
            Pattern:     regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----`),
            Severity:    "CRITICAL",
            Description: "Private key detected",
        },
        {
            Name:        "Slack Token",
            Pattern:     regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]+`),
            Severity:    "HIGH",
            Description: "Slack API token",
        },
        {
            Name:        "Google API Key",
            Pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
            Severity:    "HIGH",
            Description: "Google API key",
        },
    }
}