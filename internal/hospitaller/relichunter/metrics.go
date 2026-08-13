package relichunter

import (
	"fmt"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

// ReportMetrics gathers metrics from all adapters in the coordinator
// and emits them via the shared audit logger (or Seneschal).
func ReportMetrics(coordinator *SourceCoordinator) {
	if coordinator == nil {
		return
	}

	for _, adapter := range coordinator.Adapters {
		metrics := adapter.GetMetrics()
		
		msg := fmt.Sprintf("Source: %s | Queries: %d | Success: %d | Failure: %d | AvgTime: %v",
			adapter.Name(),
			metrics.QueryCount,
			metrics.SuccessCount,
			metrics.FailureCount,
			metrics.AverageQueryTime,
		)

		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "SOURCE_METRICS",
			Message:   msg,
		})
	}
}
