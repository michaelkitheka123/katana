package main

import (
	"fmt"
	"os"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
)

func main() {
	key := os.Getenv("OPENROUTER_API_KEY")
	if key == "" {
		fmt.Println("ERROR: OPENROUTER_API_KEY not set")
		os.Exit(1)
	}

	client, err := llm.NewLLMClient([]shared.AIProviderConfig{{
		Name:        "openrouter",
		APIKey:      key,
		Role:        "any",
		MaxTokens:   100,
		Temperature: 0.7,
	}})
	if err != nil {
		fmt.Println("Init error:", err)
		os.Exit(1)
	}

	resp, err := client.Call("any", "Reply with exactly this text: TEMPLAR_ONLINE")
	if err != nil {
		fmt.Println("Call error:", err)
		os.Exit(1)
	}
	fmt.Println("OpenRouter response:", resp)
}
