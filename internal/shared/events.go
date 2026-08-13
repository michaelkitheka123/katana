package shared

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// EventKind classifies a campaign event for display routing.
type EventKind string

const (
	EventPhase     EventKind = "PHASE"     // phase started / completed
	EventSubdomain EventKind = "SUBDOMAIN" // subdomain discovered
	EventPort      EventKind = "PORT"      // open port/service found
	EventEndpoint  EventKind = "ENDPOINT"  // HTTP endpoint discovered
	EventVuln      EventKind = "VULN"      // vulnerability found
	EventPoC       EventKind = "POC"       // PoC generated
	EventChain     EventKind = "CHAIN"     // attack chain identified
	EventWarning   EventKind = "WARNING"   // tool failure / degraded
	EventDone      EventKind = "DONE"      // campaign complete
)

// CampaignEvent is a structured, deduplicated campaign event.
type CampaignEvent struct {
	Time    time.Time
	Kind    EventKind
	Phase   string
	Message string
	Detail  string // secondary detail line (optional)
}

// EventBus is a thread-safe channel-based event emitter.
type EventBus struct {
	mu       sync.Mutex
	ch       chan CampaignEvent
	seen     map[string]bool // dedup key → already emitted
}

// NewEventBus creates an event bus with a buffered channel.
func NewEventBus() *EventBus {
	return &EventBus{
		ch:   make(chan CampaignEvent, 512),
		seen: make(map[string]bool),
	}
}

// Emit sends an event if it hasn't been emitted before (dedup by kind+message).
func (b *EventBus) Emit(kind EventKind, phase, message, detail string) {
	key := string(kind) + "|" + message
	b.mu.Lock()
	if b.seen[key] {
		b.mu.Unlock()
		return
	}
	b.seen[key] = true
	b.mu.Unlock()

	select {
	case b.ch <- CampaignEvent{
		Time:    time.Now(),
		Kind:    kind,
		Phase:   phase,
		Message: message,
		Detail:  detail,
	}:
	default:
		// channel full — drop (non-blocking)
	}
}

// EmitAlways sends an event without dedup (for phase transitions, final results).
func (b *EventBus) EmitAlways(kind EventKind, phase, message, detail string) {
	select {
	case b.ch <- CampaignEvent{
		Time:    time.Now(),
		Kind:    kind,
		Phase:   phase,
		Message: message,
		Detail:  detail,
	}:
	default:
	}
}

// Subscribe returns the read channel.
func (b *EventBus) Subscribe() <-chan CampaignEvent {
	return b.ch
}

// Close closes the channel when the campaign ends.
func (b *EventBus) Close() {
	close(b.ch)
}

// Global event bus — set by Grand Master at campaign start.
var GlobalBus *EventBus

// kindColor returns an ANSI color prefix for each event kind.
func kindColor(k EventKind) string {
	switch k {
	case EventPhase:
		return "\033[1;36m" // bold cyan
	case EventSubdomain:
		return "\033[0;34m" // blue
	case EventPort:
		return "\033[0;32m" // green
	case EventEndpoint:
		return "\033[0;37m" // white
	case EventVuln:
		return "\033[1;31m" // bold red
	case EventPoC:
		return "\033[0;33m" // yellow
	case EventChain:
		return "\033[1;35m" // bold magenta
	case EventWarning:
		return "\033[0;33m" // yellow
	case EventDone:
		return "\033[1;32m" // bold green
	default:
		return "\033[0m"
	}
}

const reset = "\033[0m"

// FormatEvent returns a clean, single-line formatted event string.
func FormatEvent(e CampaignEvent) string {
	timestamp := e.Time.Format("15:04:05")
	tag := fmt.Sprintf("%-10s", "["+string(e.Kind)+"]")
	color := kindColor(e.Kind)

	line := fmt.Sprintf("%s  %s%s%s  %s", timestamp, color, tag, reset, e.Message)
	if e.Detail != "" {
		line += "\n" + strings.Repeat(" ", 12) + "  " + e.Detail
	}
	return line
}
