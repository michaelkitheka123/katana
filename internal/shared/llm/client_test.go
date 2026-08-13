package llm

import (
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Property 16: LLM Retry Backoff Bounds
func TestCalculateBackoff_Bounds(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Test attempt sequence from 1 to 5
		for attempt := 1; attempt <= 5; attempt++ {
			delay := CalculateBackoff(attempt)
			
			// Bound check: delay should be roughly between attempt's minimum and 60 seconds + 10%
			if delay < 900*time.Millisecond {
				rt.Fatalf("Delay too small at attempt %d: %v", attempt, delay)
			}
			
			if delay > 66*time.Second { // 60s + 10% jitter maximum
				rt.Fatalf("Delay too large at attempt %d: %v", attempt, delay)
			}
		}
	})
}
