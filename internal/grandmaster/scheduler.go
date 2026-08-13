// Package grandmaster implements the Grand Master orchestrator and its
// supporting concurrency scheduler.
package grandmaster

// Scheduler enforces a concurrency limit on parallel sub-agent goroutines
// and provides a configurable per-host request rate.
type Scheduler struct {
	maxConcurrency int
	ratePerSec     int
	semaphore      chan struct{}
}

// NewScheduler creates a Scheduler. If ratePerSec is 0 it defaults to 10.
// The internal semaphore is sized to 10 concurrent slots (a reasonable
// default; the Grand Master may call SetMaxConcurrency to change it).
func NewScheduler(ratePerSec int) *Scheduler {
	if ratePerSec <= 0 {
		ratePerSec = 10
	}
	maxC := 10
	return &Scheduler{
		maxConcurrency: maxC,
		ratePerSec:     ratePerSec,
		semaphore:      make(chan struct{}, maxC),
	}
}

// SetMaxConcurrency rebuilds the semaphore with the new limit.
// Must be called before any Acquire/Release pair.
func (s *Scheduler) SetMaxConcurrency(n int) {
	if n <= 0 {
		n = 1
	}
	s.maxConcurrency = n
	s.semaphore = make(chan struct{}, n)
}

// Acquire blocks until a concurrency slot is available.
func (s *Scheduler) Acquire() {
	s.semaphore <- struct{}{}
}

// Release frees a concurrency slot.
func (s *Scheduler) Release() {
	<-s.semaphore
}
