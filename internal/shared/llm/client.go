package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

var supportedProviders = map[string]bool{
	"openai":     true,
	"anthropic":  true,
	"google":     true,
	"ollama":     true,
	"openrouter": true,
}

// providerBaseURL maps provider names to their chat completion endpoints.
var providerBaseURL = map[string]string{
	"openai":     "https://api.openai.com/v1/chat/completions",
	"anthropic":  "https://api.anthropic.com/v1/messages",
	"openrouter": "https://openrouter.ai/api/v1/chat/completions",
	"ollama":     "http://localhost:11434/api/chat",
}

// defaultModel maps provider names to sensible defaults.
var defaultModel = map[string]string{
	"openai":     "gpt-4o",
	"anthropic":  "claude-3-5-sonnet-20241022",
	"openrouter": "openai/gpt-4o",
	"ollama":     "llama3",
	"google":     "gemini-1.5-pro",
}

// LLMClient manages AI providers and routes requests.
type LLMClient struct {
	Providers  []shared.AIProviderConfig
	HTTPClient *http.Client
}

// NewLLMClient initialises the client and validates providers.
func NewLLMClient(providers []shared.AIProviderConfig) (*LLMClient, error) {
	for i, p := range providers {
		if !supportedProviders[strings.ToLower(p.Name)] {
			return nil, fmt.Errorf("UNSUPPORTED_PROVIDER: %s", p.Name)
		}
		if p.MaxTokens == 0 {
			providers[i].MaxTokens = 4096
		}
		if p.Temperature == 0 {
			providers[i].Temperature = 0.7
		}
	}
	return &LLMClient{
		Providers:  providers,
		HTTPClient: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// SelectProvider chooses the best provider for a given role.
func (c *LLMClient) SelectProvider(role string) (*shared.AIProviderConfig, error) {
	var fallback *shared.AIProviderConfig
	for _, p := range c.Providers {
		if p.Role == role {
			return &p, nil
		}
		if p.Role == "any" || p.Role == "" {
			fallback = &p
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("NO_PROVIDER_AVAILABLE")
}

// CalculateBackoff computes exponential backoff with ±10% jitter.
func CalculateBackoff(attempt int) time.Duration {
	if attempt > 5 {
		return 0
	}
	delayMs := 1000.0 * math.Pow(2, float64(attempt-1))
	if delayMs > 60000 {
		delayMs = 60000
	}
	jitterFactor := 0.9 + rand.Float64()*0.2
	return time.Duration(delayMs*jitterFactor) * time.Millisecond
}

// RedactAPIKeys replaces known API key values with [REDACTED].
func RedactAPIKeys(input string, keys []string) string {
	redacted := input
	for _, key := range keys {
		if key != "" && len(key) > 5 {
			redacted = strings.ReplaceAll(redacted, key, "[REDACTED]")
		}
	}
	return redacted
}

// ── OpenAI-compatible request/response structs ────────────────────────────────

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		// Anthropic direct API uses different field names.
		Text string `json:"text,omitempty"`
	} `json:"choices"`

// parseMessages extracts SYSTEM/USER formatted messages from a prompt
func parseMessages(prompt string) []chatMessage {
	lines := strings.Split(prompt, "\n")
	var messages []chatMessage
	var currentRole string
	var currentContent strings.Builder

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "SYSTEM:") {
			// Save previous message if any
			if currentRole != "" && currentContent.Len() > 0 {
				messages = append(messages, chatMessage{
					Role:    currentRole,
					Content: strings.TrimSpace(currentContent.String()),
				})
				currentContent.Reset()
			}
			currentRole = "system"
			// Remove "SYSTEM:" and any following spaces
			content := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "SYSTEM:"))
			currentContent.WriteString(content)
		} else if strings.HasPrefix(trimmedLine, "USER:") {
			// Save previous message if any
			if currentRole != "" && currentContent.Len() > 0 {
				messages = append(messages, chatMessage{
					Role:    currentRole,
					Content: strings.TrimSpace(currentContent.String()),
				})
				currentContent.Reset()
			}
			currentRole = "user"
			// Remove "USER:" and any following spaces
			content := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "USER:"))
			currentContent.WriteString(content)
		} else if currentRole != "" {
			// Continue building current message
			if currentContent.Len() > 0 {
				currentContent.WriteString("\n")
			}
			currentContent.WriteString(line)
		}
	}

	// Save the last message
	if currentRole != "" && currentContent.Len() > 0 {
		messages = append(messages, chatMessage{
			Role:    currentRole,
			Content: strings.TrimSpace(currentContent.String()),
		})
	}

	return messages
}
	// OpenRouter / Anthropic error envelope.
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
	// Anthropic direct response format.
	Content []struct {
		Text string `json:"text"`
	} `json:"content,omitempty"`
}

// Call invokes the LLM for the given role and prompt, with retry logic.
func (c *LLMClient) Call(role, prompt string) (string, error) {
	provider, err := c.SelectProvider(role)
	if err != nil {
		return "", err
	}

	model := provider.Name // use provider.Name as model hint if Role embeds it,
	// otherwise fall back to the default for the provider.
	if m, ok := defaultModel[strings.ToLower(provider.Name)]; ok {
		model = m
	}

	keys := []string{provider.APIKey}

	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		resp, httpStatus, err := c.doCall(provider, model, prompt)
		if err == nil {
			return resp, nil
		}
		// Retry on rate limit or server error.
		if httpStatus == 429 || (httpStatus >= 500 && httpStatus < 600) {
			lastErr = err
			delay := CalculateBackoff(attempt)
			time.Sleep(delay)
			continue
		}
		// Non-retryable error.
		return "", fmt.Errorf("%s", RedactAPIKeys(err.Error(), keys))
	}

	errMsg := RedactAPIKeys(
		fmt.Sprintf("LLM call failed after 5 retries (provider: %s): %v", provider.Name, lastErr),
		keys,
	)
	return "", fmt.Errorf("%s", errMsg)
}

// doCall performs a single HTTP request to the provider's API.
// Returns the response text, HTTP status code, and any error.
func (c *LLMClient) doCall(provider *shared.AIProviderConfig, model, prompt string) (string, int, error) {
	baseURL, ok := providerBaseURL[strings.ToLower(provider.Name)]
	if !ok {
		// Unknown provider — attempt OpenAI-compatible endpoint.
		baseURL = "https://api.openai.com/v1/chat/completions"
	}

	// Parse SYSTEM/USER format if present
	messages := parseMessages(prompt)
	if len(messages) == 0 {
		// Fallback to single user message
		messages = []chatMessage{
			{Role: "user", Content: prompt},
		}
	}

	reqBody := chatRequest{
		Model:       model,
		Messages:    messages,
		MaxTokens:   provider.MaxTokens,
		Temperature: provider.Temperature,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", 0, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+provider.APIKey)

	// OpenRouter-specific headers (required by their API).
	if strings.ToLower(provider.Name) == "openrouter" {
		req.Header.Set("HTTP-Referer", "https://github.com/templar-framework/templar")
		req.Header.Set("X-Title", "Templar Security Framework")
	}

	httpResp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return "", httpResp.StatusCode, fmt.Errorf("read response body: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return "", httpResp.StatusCode, fmt.Errorf("HTTP %d: %s", httpResp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return "", httpResp.StatusCode, fmt.Errorf("decode response: %w", err)
	}

	// Handle error envelope.
	if chatResp.Error != nil {
		return "", httpResp.StatusCode, fmt.Errorf("API error %d: %s", chatResp.Error.Code, chatResp.Error.Message)
	}

	// Extract text — OpenAI/OpenRouter format.
	if len(chatResp.Choices) > 0 {
		if chatResp.Choices[0].Message.Content != "" {
			return chatResp.Choices[0].Message.Content, 200, nil
		}
		if chatResp.Choices[0].Text != "" {
			return chatResp.Choices[0].Text, 200, nil
		}
	}

	// Anthropic direct format.
	if len(chatResp.Content) > 0 && chatResp.Content[0].Text != "" {
		return chatResp.Content[0].Text, 200, nil
	}

	return "", 200, fmt.Errorf("LLM response had no usable content")
}
