package seneschal

import (
	"errors"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

type ProgressEvent struct {
	CampaignID    string
	PhaseName     string
	PhaseStatus   string
	SubdomainCount int
	EndpointCount  int
	VulnCount      int
	PoCCount       int
	ChainCount     int
	Timestamp      time.Time
}

type StateManager struct {
	mu           sync.RWMutex
	state        shared.CampaignState
	eventChannel chan ProgressEvent
}

func NewStateManager() *StateManager {
	return &StateManager{
		eventChannel: make(chan ProgressEvent, 100),
	}
}

// InitializeCampaign sets up a new campaign state
func (s *StateManager) InitializeCampaign(campaignID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.ID != "" && s.state.ID != campaignID {
		return errors.New("a campaign is already initialized")
	}

	s.state = shared.CampaignState{
		ID:     campaignID,
		Status: "running",
		Phases: map[string]string{
			"preceptor":   "pending",
			"hospitaller": "pending",
			"marshal":     "pending",
			"chaplain":    "pending",
			"scribe":      "pending",
		},
	}

	return nil
}

// GetStatus returns the overall campaign status
func (s *StateManager) GetStatus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Status
}

// GetPhasesStatus returns a copy of all phase statuses
func (s *StateManager) GetPhasesStatus() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	copyMap := make(map[string]string)
	for k, v := range s.state.Phases {
		copyMap[k] = v
	}
	return copyMap
}

// SetPhaseStatus updates a phase and emits an event
// Transitions allowed: pending -> running -> complete | degraded
func (s *StateManager) SetPhaseStatus(phaseName string, newStatus string, counts ProgressEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	currentStatus, exists := s.state.Phases[phaseName]
	if !exists {
		return errors.New("unknown phase")
	}

	// Validate transitions
	if currentStatus == "pending" && newStatus != "running" && newStatus != "complete" && newStatus != "degraded" {
		return errors.New("invalid transition from pending")
	}
	if currentStatus == "running" && newStatus != "complete" && newStatus != "degraded" {
		return errors.New("invalid transition from running")
	}
	if currentStatus == "complete" || currentStatus == "degraded" {
		return errors.New("phase already in terminal state")
	}

	s.state.Phases[phaseName] = newStatus
	
	counts.CampaignID = s.state.ID
	counts.PhaseName = phaseName
	counts.PhaseStatus = newStatus
	counts.Timestamp = time.Now().UTC()

	// Non-blocking event emit
	select {
	case s.eventChannel <- counts:
	default:
		// channel full, drop or log (in a real app, maybe log a warning)
	}

	return nil
}

// UpdateStatus is a simplified wrapper used by the coordinator
func (s *StateManager) UpdateStatus(campaignID, status, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Status = status
	// The real system would likely log the message or fire an event
}

// SubscribeEvents allows consumers to listen to state change events
func (s *StateManager) SubscribeEvents() <-chan ProgressEvent {
	return s.eventChannel
}
