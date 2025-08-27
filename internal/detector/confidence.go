package detector

import (
	"math"
	"strings"
)

// ConfidenceCalculator calculates confidence scores for secret detections
type ConfidenceCalculator struct {
    entropyThreshold float64
}

func NewConfidenceCalculator() *ConfidenceCalculator {
    return &ConfidenceCalculator{
        entropyThreshold: 3.5, // Minimum entropy for high confidence
    }
}

// CalculateConfidence computes a confidence score (0.0 to 1.0) for a detected secret
func (cc *ConfidenceCalculator) CalculateConfidence(secret, context, secretType string) float64 {
    var factors []float64
    
    // Factor 1: Pattern specificity (0.0 - 1.0)
    patternSpecificity := cc.calculatePatternSpecificity(secret, secretType)
    factors = append(factors, patternSpecificity)
    
    // Factor 2: Entropy analysis (0.0 - 1.0)
    entropyScore := cc.calculateEntropyScore(secret)
    factors = append(factors, entropyScore)
    
    // Factor 3: Context analysis (0.0 - 1.0)
    contextScore := cc.calculateContextScore(context, secretType)
    factors = append(factors, contextScore)
    
    // Factor 4: Length appropriateness (0.0 - 1.0)
    lengthScore := cc.calculateLengthScore(secret, secretType)
    factors = append(factors, lengthScore)
    
    // Factor 5: Character composition (0.0 - 1.0)
    compositionScore := cc.calculateCompositionScore(secret, secretType)
    factors = append(factors, compositionScore)
    
    // Weighted average with emphasis on pattern specificity and entropy
    weights := []float64{0.3, 0.25, 0.2, 0.15, 0.1}
    
    var weightedSum, totalWeight float64
    for i, factor := range factors {
        if i < len(weights) {
            weightedSum += factor * weights[i]
            totalWeight += weights[i]
        }
    }
    
    confidence := weightedSum / totalWeight
    
    // Apply penalties for common false positive indicators
    confidence = cc.applyFalsePositivePenalties(secret, context, confidence)
    
    // Ensure confidence is within bounds
    if confidence < 0.0 {
        confidence = 0.0
    }
    if confidence > 1.0 {
        confidence = 1.0
    }
    
    return confidence
}

// calculatePatternSpecificity evaluates how specific the pattern match is
func (cc *ConfidenceCalculator) calculatePatternSpecificity(secret, secretType string) float64 {
    specificityScores := map[string]float64{
        "AWS Access Key":     0.95, // Very specific format
        "GitHub Token":       0.98, // Highly specific prefix
        "Private Key":        0.99, // Very distinctive format
        "Google API Key":     0.90, // Specific prefix pattern
        "Slack Token":        0.92, // Specific prefix patterns
        "Database URL":       0.85, // Protocol-specific
        "JWT Token":          0.75, // Common format, but can vary
        "API Key Generic":    0.50, // Generic pattern, less specific
        "AWS Secret Key":     0.60, // Base64-like, less specific
    }
    
    if score, exists := specificityScores[secretType]; exists {
        return score
    }
    
    return 0.5 // Default moderate specificity
}

// calculateEntropyScore measures the randomness of the secret
func (cc *ConfidenceCalculator) calculateEntropyScore(secret string) float64 {
    entropy := cc.calculateShannonEntropy(secret)
    
    // Normalize entropy score (typical range 0-6, we want 0-1)
    normalizedEntropy := entropy / 6.0
    if normalizedEntropy > 1.0 {
        normalizedEntropy = 1.0
    }
    
    // High entropy indicates more likely to be a real secret
    return normalizedEntropy
}

// calculateShannonEntropy computes Shannon entropy of a string
func (cc *ConfidenceCalculator) calculateShannonEntropy(s string) float64 {
    if len(s) == 0 {
        return 0
    }
    
    // Count character frequencies
    freq := make(map[rune]int)
    for _, char := range s {
        freq[char]++
    }
    
    // Calculate entropy
    var entropy float64
    length := float64(len(s))
    
    for _, count := range freq {
        p := float64(count) / length
        if p > 0 {
            entropy -= p * math.Log2(p)
        }
    }
    
    return entropy
}

// calculateContextScore analyzes the surrounding context
func (cc *ConfidenceCalculator) calculateContextScore(context, secretType string) float64 {
    if context == "" {
        return 0.5 // Neutral if no context
    }
    
    lowerContext := strings.ToLower(context)
    
    // Positive indicators
    positiveKeywords := []string{
        "key", "secret", "token", "password", "credential", "auth",
        "api", "private", "access", "bearer", "jwt", "oauth",
    }
    
    // Negative indicators (test/example contexts)
    negativeKeywords := []string{
        "test", "example", "demo", "sample", "placeholder", "fake",
        "mock", "dummy", "template", "documentation", "readme",
        "tutorial", "guide", "comment", "todo", "fixme",
    }
    
    var positiveScore, negativeScore float64
    
    for _, keyword := range positiveKeywords {
        if strings.Contains(lowerContext, keyword) {
            positiveScore += 0.2
        }
    }
    
    for _, keyword := range negativeKeywords {
        if strings.Contains(lowerContext, keyword) {
            negativeScore += 0.3
        }
    }
    
    // Calculate final context score
    contextScore := 0.5 + positiveScore - negativeScore
    
    if contextScore < 0.0 {
        contextScore = 0.0
    }
    if contextScore > 1.0 {
        contextScore = 1.0
    }
    
    return contextScore
}

// calculateLengthScore evaluates if the secret length is appropriate for its type
func (cc *ConfidenceCalculator) calculateLengthScore(secret, secretType string) float64 {
    length := len(secret)
    
    // Expected length ranges for different secret types
    lengthRanges := map[string][2]int{
        "AWS Access Key":     {20, 20},   // Exactly 20 chars
        "AWS Secret Key":     {40, 40},   // Exactly 40 chars
        "GitHub Token":       {40, 40},   // ghp_ + 36 chars
        "Google API Key":     {39, 39},   // AIza + 35 chars
        "JWT Token":          {50, 500},  // Variable, but typically long
        "API Key Generic":    {16, 64},   // Common range
        "Slack Token":        {24, 56},   // Various formats
        "Database URL":       {20, 200},  // Variable length
        "Private Key":        {100, 5000}, // Very variable
    }
    
    if expectedRange, exists := lengthRanges[secretType]; exists {
        minLen, maxLen := expectedRange[0], expectedRange[1]
        
        if length >= minLen && length <= maxLen {
            return 1.0 // Perfect length
        } else if length < minLen {
            // Too short - penalize more severely
            ratio := float64(length) / float64(minLen)
            return ratio * 0.5
        } else {
            // Too long - penalize less severely
            ratio := float64(maxLen) / float64(length)
            return 0.5 + (ratio * 0.5)
        }
    }
    
    return 0.7 // Default for unknown types
}

// calculateCompositionScore analyzes character composition
func (cc *ConfidenceCalculator) calculateCompositionScore(secret, secretType string) float64 {
    var score float64 = 0.5 // Base score
    
    // Count different character types
    var hasUpper, hasLower, hasDigit, hasSpecial bool
    var upperCount, lowerCount, digitCount, specialCount int
    
    for _, char := range secret {
        switch {
        case char >= 'A' && char <= 'Z':
            hasUpper = true
            upperCount++
        case char >= 'a' && char <= 'z':
            hasLower = true
            lowerCount++
        case char >= '0' && char <= '9':
            hasDigit = true
            digitCount++
        default:
            hasSpecial = true
            specialCount++
        }
    }
    
    // Diversity bonus
    diversity := 0
    if hasUpper { diversity++ }
    if hasLower { diversity++ }
    if hasDigit { diversity++ }
    if hasSpecial { diversity++ }
    
    score += float64(diversity) * 0.1
    
    // Type-specific composition analysis
    switch secretType {
    case "AWS Access Key":
        // Should be all uppercase alphanumeric
        if hasUpper && hasDigit && !hasLower && !hasSpecial {
            score += 0.3
        }
    case "JWT Token":
        // Should have base64-like composition
        if hasUpper && hasLower && hasDigit && specialCount <= 2 {
            score += 0.2
        }
    case "Private Key":
        // Should have specific format indicators
        if hasUpper && hasLower && hasSpecial {
            score += 0.3
        }
    }
    
    // Penalize if too uniform (like all same character)
    totalChars := len(secret)
    if totalChars > 0 {
        maxSingleType := upperCount
        if lowerCount > maxSingleType { maxSingleType = lowerCount }
        if digitCount > maxSingleType { maxSingleType = digitCount }
        if specialCount > maxSingleType { maxSingleType = specialCount }
        
        uniformity := float64(maxSingleType) / float64(totalChars)
        if uniformity > 0.8 {
            score -= 0.2 // Penalty for high uniformity
        }
    }
    
    if score > 1.0 { score = 1.0 }
    if score < 0.0 { score = 0.0 }
    
    return score
}

// applyFalsePositivePenalties reduces confidence for common false positives
func (cc *ConfidenceCalculator) applyFalsePositivePenalties(secret, context string, confidence float64) float64 {
    lowerSecret := strings.ToLower(secret)
    lowerContext := strings.ToLower(context)
    
    // Common false positive patterns
    falsePositivePatterns := []string{
        "example", "test", "demo", "sample", "placeholder",
        "your-api-key", "insert-key-here", "replace-with",
        "akiaxxxxxxxxtest", "akiaiosfodnn7example",
        "aaaaaaaaaaaaaaaaaaaa", "1111111111111111111",
        "abcdefghijklmnopqrstuvwxyz", "0123456789",
    }
    
    for _, pattern := range falsePositivePatterns {
        if strings.Contains(lowerSecret, pattern) || strings.Contains(lowerContext, pattern) {
            confidence *= 0.1 // Severe penalty
            break
        }
    }
    
    // Repetitive patterns penalty
    if cc.isRepetitive(secret) {
        confidence *= 0.3
    }
    
    // All same character penalty
    if cc.isAllSameCharacter(secret) {
        confidence *= 0.1
    }
    
    return confidence
}

// isRepetitive checks if the string has repetitive patterns
func (cc *ConfidenceCalculator) isRepetitive(s string) bool {
    if len(s) < 4 {
        return false
    }
    
    // Check for patterns like "abcabc" or "123123"
    for patternLen := 2; patternLen <= len(s)/2; patternLen++ {
        if patternLen > len(s) {
            break
        }
        pattern := s[:patternLen]
        repeated := strings.Repeat(pattern, len(s)/patternLen)
        if len(repeated) >= len(s) - patternLen {
            // Ensure we don't slice beyond string bounds
            compareLen := len(s)
            if len(repeated) < compareLen {
                compareLen = len(repeated)
            }
            if strings.HasPrefix(s, repeated[:compareLen]) {
                return true
            }
        }
    }
    
    return false
}

// isAllSameCharacter checks if all characters are the same
func (cc *ConfidenceCalculator) isAllSameCharacter(s string) bool {
    if len(s) <= 1 {
        return false
    }
    
    first := s[0]
    for i := 1; i < len(s); i++ {
        if s[i] != first {
            return false
        }
    }
    return true
}