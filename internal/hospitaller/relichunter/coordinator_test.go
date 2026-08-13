package relichunter

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

// mockFailingAdapter always returns an error or blocks until context cancellation
type mockFailingAdapter struct {
	name      string
	shouldErr bool
	block     bool
	enabled   bool
}

func (m *mockFailingAdapter) Name() string { return m.name }
func (m *mockFailingAdapter) Type() SourceType { return SourceTypeVulnerabilityFeed }
func (m *mockFailingAdapter) IsEnabled() bool { return m.enabled }
func (m *mockFailingAdapter) SetEnabled(enabled bool) { m.enabled = enabled }
func (m *mockFailingAdapter) GetMetrics() SourceMetrics { return SourceMetrics{} }
func (m *mockFailingAdapter) HealthCheck(ctx context.Context) error { return nil }

func (m *mockFailingAdapter) Query(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	if m.shouldErr {
		return nil, fmt.Errorf("simulated failure")
	}
	if m.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, nil
}

// mockSuccessAdapter returns a specific set of vulns
type mockSuccessAdapter struct {
	name    string
	vulns   []shared.Vulnerability
	enabled bool
}

func (m *mockSuccessAdapter) Name() string { return m.name }
func (m *mockSuccessAdapter) Type() SourceType { return SourceTypeVulnerabilityFeed }
func (m *mockSuccessAdapter) IsEnabled() bool { return m.enabled }
func (m *mockSuccessAdapter) SetEnabled(enabled bool) { m.enabled = enabled }
func (m *mockSuccessAdapter) GetMetrics() SourceMetrics { return SourceMetrics{} }
func (m *mockSuccessAdapter) HealthCheck(ctx context.Context) error { return nil }

func (m *mockSuccessAdapter) Query(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	return m.vulns, nil
}

func TestCoordinatorResilience(t *testing.T) {
	adapters := []SourceAdapter{
		&mockFailingAdapter{name: "failer", shouldErr: true, enabled: true},
		&mockFailingAdapter{name: "blocker", block: true, enabled: true},
		&mockSuccessAdapter{
			name: "success",
			enabled: true,
			vulns: []shared.Vulnerability{
				{ID: "CVE-2023-1234", Title: "Success Vuln", Severity: "high", CVSSScore: 7.5, Status: "confirmed"},
			},
		},
	}

	coordinator := NewSourceCoordinator(adapters, 1*time.Minute)

	// Use a short timeout to trip the blocker
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	tech := shared.TechStackEntry{Name: "test"}
	start := time.Now()
	vulns, err := coordinator.QueryAll(ctx, tech)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Coordinator should not fail on individual adapter errors, got: %v", err)
	}

	if len(vulns) != 1 || vulns[0].ID != "CVE-2023-1234" {
		t.Errorf("Expected 1 vuln from success adapter, got %d", len(vulns))
	}

	if elapsed > 100*time.Millisecond {
		t.Errorf("Coordinator took too long: %v (expected ~50ms)", elapsed)
	}
}
