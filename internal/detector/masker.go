package detector

import (
	"strings"
)

func maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	
	// Handle multi-line secrets (like private keys)
	if strings.Contains(secret, "\n") {
		return maskMultiLineSecret(secret)
	}
	
	// Handle structured secrets (URLs, JWTs, etc.)
	if strings.Contains(secret, "://") {
		return maskURLSecret(secret)
	}
	
	// Handle JWT secrets
	if strings.Count(secret, ".") == 2 && len(secret) > 50 {
		return maskJWTSecret(secret)
	}
	
	// Handle single-line secrets with identifiable prefixes
	return maskSingleLineSecret(secret)
}

func maskMultiLineSecret(secret string) string {
	lines := strings.Split(secret, "\n")
	var maskedLines []string
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		
		if line == "" || strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "Comment:") {
			maskedLines = append(maskedLines, line)
		} else if i == 1 && len(line) > 8 {
			// Show beginning of first content line for identification
			visibleChars := min(8, len(line)/3)
			maskedLines = append(maskedLines, line[:visibleChars]+"***[REDACTED]***")
		} else {
			maskedLines = append(maskedLines, "***[REDACTED]***")
		}
	}
	
	return strings.Join(maskedLines, "\n")
}

func maskURLSecret(secret string) string {
	parts := strings.SplitN(secret, "://", 2)
	if len(parts) != 2 {
		return maskSingleLineSecret(secret)
	}
	
	protocol := parts[0]
	rest := parts[1]
	
	// Look for credentials pattern
	if strings.Contains(rest, "@") {
		atIndex := strings.Index(rest, "@")
		hostPart := rest[atIndex:]
		credsPart := rest[:atIndex]
		
		// Mask credentials
		if strings.Contains(credsPart, ":") {
			userPass := strings.SplitN(credsPart, ":", 2)
			userLen := len(userPass[0])
			visibleUser := min(3, userLen/2)
			maskedCreds := userPass[0][:visibleUser] + "***:***"
			return protocol + "://" + maskedCreds + hostPart
		}
		return protocol + "://***:***" + hostPart
	}
	
	return protocol + "://" + maskSingleLineSecret(rest)
}

func maskJWTSecret(secret string) string {
	parts := strings.Split(secret, ".")
	if len(parts) == 3 {
		// Show partial header for identification, mask payload and signature
		headerLen := len(parts[0])
		visibleHeader := min(8, headerLen/2)
		return parts[0][:visibleHeader] + "***.***[PAYLOAD]***.***[SIGNATURE]***"
	}
	return maskSingleLineSecret(secret)
}

func maskSingleLineSecret(secret string) string {
	secretLen := len(secret)
	var prefixLen, suffixLen int
	
	if secretLen <= 20 {
		// Short secrets: show 25% from start, 15% from end
		prefixLen = max(2, secretLen/4)
		suffixLen = max(1, secretLen/7)
	} else if secretLen <= 50 {
		// Medium secrets: show more absolute characters
		prefixLen = max(4, secretLen/6)
		suffixLen = max(2, secretLen/8)
	} else {
		// Long secrets: show fixed amount for identification
		prefixLen = max(6, secretLen/8)
		suffixLen = max(3, secretLen/10)
	}
	
	// Ensure we don't show too much (max 20% of total)
	maxVisible := max(4, secretLen/5)
	if prefixLen+suffixLen > maxVisible {
		ratio := float64(maxVisible) / float64(prefixLen+suffixLen)
		prefixLen = int(float64(prefixLen) * ratio)
		suffixLen = int(float64(suffixLen) * ratio)
	}
	
	// Ensure minimum masking
	if prefixLen + suffixLen >= secretLen - 2 {
		prefixLen = min(prefixLen, secretLen/3)
		suffixLen = min(suffixLen, secretLen/4)
	}
	
	maskedLen := secretLen - prefixLen - suffixLen
	return secret[:prefixLen] + strings.Repeat("*", maskedLen) + secret[secretLen-suffixLen:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
