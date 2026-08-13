package grandmaster

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/templar-framework/templar/internal/chaplain"
	"github.com/templar-framework/templar/internal/hospitaller"
	"github.com/templar-framework/templar/internal/marshal"
	"github.com/templar-framework/templar/internal/marshal/holylance"
	"github.com/templar-framework/templar/internal/preceptor"
	"github.com/templar-framework/templar/internal/scribe"
	"github.com/templar-framework/templar/internal/seneschal"
	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
	"github.com/templar-framework/templar/internal/shared/mcp"
)

const (
	statusRunning  = "running"
	statusPaused   = "paused"
	statusAborted  = "aborted"
	statusComplete = "complete"
)

// GrandMaster is the central campaign orchestrator. It sequences all Knights,
// manages campaign lifecycle (start / pause / resume / abort), enforces
// concurrency limits, and wires results between phases.
type GrandMaster struct {
	Store     *seneschal.Store
	State     *seneschal.StateManager
	LLMClient *llm.LLMClient
	Scheduler *Scheduler
	MCPReg    *mcp.Registry
	config    shared.CrusadeConfig

	mu         sync.Mutex
	status     string
	pauseCh    chan struct{} // closed/re-created on pause/resume
	abortCh    chan struct{} // closed on abort
	knights    map[string]shared.IKnight
}

// NewGrandMaster validates config, initialises infrastructure, and returns a
// ready-to-use GrandMaster. Returns an error if config is invalid or if any
// required subsystem fails to start.
func NewGrandMaster(dbPath string, config shared.CrusadeConfig) (*GrandMaster, error) {
	// --- config validation ---
	if strings.TrimSpace(config.TargetURL) == "" {
		return nil, errors.New("GrandMaster: config.TargetURL must not be empty")
	}
	if len(config.Scope.AllowedDomains) == 0 {
		return nil, errors.New("SCOPE_CONFIGURATION_ERROR: config.Scope.AllowedDomains must not be empty")
	}
	hasProvider := false
	for _, p := range config.AIProviders {
		if strings.TrimSpace(p.APIKey) != "" {
			hasProvider = true
			break
		}
	}
	if !hasProvider {
		return nil, errors.New("NO_AI_PROVIDER: at least one AIProviderConfig with a non-empty APIKey is required")
	}
	if strings.TrimSpace(config.OutputDir) == "" {
		return nil, errors.New("GrandMaster: config.OutputDir must not be empty")
	}

	// --- infrastructure ---
	store, err := seneschal.NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("GrandMaster: failed to init store: %w", err)
	}

	llmClient, err := llm.NewLLMClient(config.AIProviders)
	if err != nil {
		// Non-fatal for mock/test providers; log and continue.
		log.Printf("GrandMaster: LLM client init warning: %v", err)
		llmClient = nil
	}

	ratePerSec := config.RateLimit.RequestsPerSecond
	scheduler := NewScheduler(ratePerSec)

	// Initialise MCP registry from config (non-fatal if servers fail to start).
	mcpReg := mcp.InitFromConfig(config.MCPServers)

	// Initialise global event bus for structured campaign output.
	shared.GlobalBus = shared.NewEventBus()

	return &GrandMaster{
		Store:     store,
		State:     seneschal.NewStateManager(),
		LLMClient: llmClient,
		Scheduler: scheduler,
		MCPReg:    mcpReg,
		config:    config,
		status:    statusRunning,
		pauseCh:   make(chan struct{}),
		abortCh:   make(chan struct{}),
		knights:   make(map[string]shared.IKnight),
	}, nil
}

// RegisterKnight registers an optional custom Knight by name. Built-in Knights
// (Preceptor, Hospitaller, etc.) are always used regardless.
func (gm *GrandMaster) RegisterKnight(name string, knight shared.IKnight) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.knights[name] = knight
}

// GetStatus returns the current campaign status string.
func (gm *GrandMaster) GetStatus() string {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.status
}

// Pause suspends a running campaign. Returns CAMPAIGN_NOT_RUNNING if not running.
func (gm *GrandMaster) Pause() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.status != statusRunning {
		return fmt.Errorf("CAMPAIGN_NOT_RUNNING: current status is %q", gm.status)
	}
	gm.status = statusPaused
	close(gm.pauseCh)
	return nil
}

// Resume continues a paused campaign. Returns CAMPAIGN_NOT_PAUSED if not paused.
func (gm *GrandMaster) Resume() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.status != statusPaused {
		return fmt.Errorf("CAMPAIGN_NOT_PAUSED: current status is %q", gm.status)
	}
	gm.status = statusRunning
	gm.pauseCh = make(chan struct{}) // reset for next pause
	return nil
}

// Abort terminates a running or paused campaign immediately.
// Returns CAMPAIGN_ALREADY_TERMINAL if already aborted or complete.
func (gm *GrandMaster) Abort() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.status == statusAborted || gm.status == statusComplete {
		return fmt.Errorf("CAMPAIGN_ALREADY_TERMINAL: current status is %q", gm.status)
	}
	gm.status = statusAborted
	close(gm.abortCh)
	return nil
}

// isAborted returns true if the abort channel has been closed.
func (gm *GrandMaster) isAborted() bool {
	select {
	case <-gm.abortCh:
		return true
	default:
		return false
	}
}

// setPhase transitions a phase to the given status and emits a progress event.
func (gm *GrandMaster) setPhase(phase, status string, event seneschal.ProgressEvent) {
	if err := gm.State.SetPhaseStatus(phase, status, event); err != nil {
		log.Printf("GrandMaster: setPhase %s→%s: %v", phase, status, err)
	}
}

// StartCrusade runs the full campaign pipeline for the given campaignID.
// Phases: Preceptor → Hospitaller → Marshal → Chaplain → Scribe.
func (gm *GrandMaster) StartCrusade(campaignID string) (*shared.CampaignResult, error) {
	// Duplicate-campaign guard.
	if gm.State.GetStatus() == statusRunning || gm.State.GetStatus() == statusPaused {
		return nil, fmt.Errorf("DUPLICATE_CAMPAIGN: a campaign is already active for %s", gm.config.TargetURL)
	}

	if err := gm.State.InitializeCampaign(campaignID); err != nil {
		return nil, fmt.Errorf("GrandMaster: failed to init campaign state: %w", err)
	}

	result := &shared.CampaignResult{CampaignID: campaignID}

	// ── Phase 1: Preceptor ──────────────────────────────────────────────────
	if gm.isAborted() {
		return result, fmt.Errorf("campaign aborted before Preceptor phase")
	}
	gm.setPhase("preceptor", "running", seneschal.ProgressEvent{})
	if shared.GlobalBus != nil {
		shared.GlobalBus.EmitAlways(shared.EventPhase, "preceptor", "⚔  Phase 1/5: PRECEPTOR — Reconnaissance started", "")
	}

	prec := preceptor.NewPreceptorWithMCP(gm.config.Scope, gm.MCPReg)
	surface, err := prec.Run(gm.config)
	if err != nil {
		log.Printf("GrandMaster: Preceptor degraded: %v", err)
		gm.setPhase("preceptor", "degraded", seneschal.ProgressEvent{})
	} else {
		_ = gm.Store.StoreReconResults(campaignID, surface)
		result.AttackSurface = surface
		gm.setPhase("preceptor", "complete", seneschal.ProgressEvent{
			SubdomainCount: len(surface.Subdomains),
			EndpointCount:  len(surface.Endpoints),
		})
		if shared.GlobalBus != nil {
			shared.GlobalBus.EmitAlways(shared.EventPhase, "preceptor",
				fmt.Sprintf("✓  PRECEPTOR complete — %d subdomains, %d hosts, %d endpoints",
					len(surface.Subdomains), len(surface.Hosts), len(surface.Endpoints)), "")
		}
		// LLM scope refinement (best-effort, non-blocking).
		gm.refineScope(surface)
	}

	// ── Phase 2: Hospitaller ────────────────────────────────────────────────
	if gm.isAborted() {
		return result, fmt.Errorf("campaign aborted before Hospitaller phase")
	}
	gm.setPhase("hospitaller", "running", seneschal.ProgressEvent{})
	if shared.GlobalBus != nil {
		shared.GlobalBus.EmitAlways(shared.EventPhase, "hospitaller", "⚔  Phase 2/5: HOSPITALLER — Vulnerability Analysis started", "")
	}

	hosp := hospitaller.NewHospitallerWithMCP(gm.Store, gm.LLMClient, gm.MCPReg)
	vulns, err := hosp.Run(campaignID, result.AttackSurface)
	if err != nil {
		log.Printf("GrandMaster: Hospitaller degraded: %v", err)
		gm.setPhase("hospitaller", "degraded", seneschal.ProgressEvent{})
	} else {
		result.Vulnerabilities = vulns
		gm.setPhase("hospitaller", "complete", seneschal.ProgressEvent{
			VulnCount: len(vulns),
		})
	}

	// ── Phase 3: Marshal ────────────────────────────────────────────────────
	if gm.isAborted() {
		return result, fmt.Errorf("campaign aborted before Marshal phase")
	}
	gm.setPhase("marshal", "running", seneschal.ProgressEvent{})

	gen, genErr := holylance.NewGenerator(gm.LLMClient, nil)
	if genErr != nil {
		log.Printf("GrandMaster: Holy Lance init failed, Marshal degraded: %v", genErr)
		gm.setPhase("marshal", "degraded", seneschal.ProgressEvent{})
	} else {
		m := marshal.NewMarshal(gen, gm.Store, false)
		pocs, err := m.ForgeExploits(campaignID, result.Vulnerabilities)
		if err != nil {
			log.Printf("GrandMaster: Marshal degraded: %v", err)
			gm.setPhase("marshal", "degraded", seneschal.ProgressEvent{})
		} else {
			result.PoCs = pocs
			gm.setPhase("marshal", "complete", seneschal.ProgressEvent{
				PoCCount: len(pocs),
			})
		}
	}

	// ── Phase 4: Chaplain ───────────────────────────────────────────────────
	if gm.isAborted() {
		return result, fmt.Errorf("campaign aborted before Chaplain phase")
	}
	gm.setPhase("chaplain", "running", seneschal.ProgressEvent{})

	chap := chaplain.NewChaplain(gm.Store, gm.LLMClient)
	chains, err := chap.PlanChains(campaignID, result.Vulnerabilities)
	if err != nil {
		log.Printf("GrandMaster: Chaplain degraded: %v", err)
		gm.setPhase("chaplain", "degraded", seneschal.ProgressEvent{})
	} else {
		result.AttackChains = chains
		gm.setPhase("chaplain", "complete", seneschal.ProgressEvent{
			ChainCount: len(chains),
		})
	}

	// ── Phase 5: Scribe ─────────────────────────────────────────────────────
	if gm.isAborted() {
		return result, fmt.Errorf("campaign aborted before Scribe phase")
	}
	gm.setPhase("scribe", "running", seneschal.ProgressEvent{})

	sc := scribe.NewScribe(gm.Store)
	formats := []string{"json", "markdown", "html", "sarif"}
	if _, err := sc.WriteChronicle(campaignID, gm.config.OutputDir, formats); err != nil {
		log.Printf("GrandMaster: Scribe degraded: %v", err)
		gm.setPhase("scribe", "degraded", seneschal.ProgressEvent{})
	} else {
		gm.setPhase("scribe", "complete", seneschal.ProgressEvent{})
	}

	// ── Campaign complete ───────────────────────────────────────────────────
	gm.mu.Lock()
	gm.status = statusComplete
	gm.mu.Unlock()
	gm.State.UpdateStatus(campaignID, shared.CampaignStatusCompleted, "All phases complete")

	return result, nil
}

// refineScope calls the LLM with an orchestration prompt to optionally suggest
// scope adjustments. The response is logged but scope is not mutated automatically.
func (gm *GrandMaster) refineScope(surface shared.AttackSurface) {
	if gm.LLMClient == nil {
		return
	}
	prompt := fmt.Sprintf(
		"Attack surface summary: %d subdomains, %d hosts, %d endpoints discovered for target %s. "+
			"Suggest any additional subdomains or paths that should be included or excluded from scope.",
		len(surface.Subdomains), len(surface.Hosts), len(surface.Endpoints), gm.config.TargetURL,
	)
	resp, err := gm.LLMClient.Call("orchestration", prompt)
	if err != nil {
		log.Printf("GrandMaster: LLM scope refinement call failed: %v", err)
		return
	}
	log.Printf("GrandMaster: LLM scope refinement suggestion: %s", resp)
}
