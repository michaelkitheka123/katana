// Command templar — Pilgrim CLI entry point for the Templar cybersecurity framework.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/templar-framework/templar/internal/grandmaster"
	"github.com/templar-framework/templar/internal/shared"
	"gopkg.in/yaml.v3"
)

// ── Config file schema ────────────────────────────────────────────────────────

// CrusadeConfigFile is the YAML schema accepted by --config.
type CrusadeConfigFile struct {
	TargetURL      string   `yaml:"target_url"`
	AllowedDomains []string `yaml:"allowed_domains"`
	ExcludedPaths  []string `yaml:"excluded_paths"`
	ScanDepth      string   `yaml:"scan_depth"`
	OutputDir      string   `yaml:"output_dir"`
	AIProviders []struct {
		Name        string  `yaml:"name"`
		APIKey      string  `yaml:"api_key"`
		Role        string  `yaml:"role"`
		MaxTokens   int     `yaml:"max_tokens"`
		Temperature float64 `yaml:"temperature"`
	} `yaml:"ai_providers"`
	MCPServers []struct {
		Name    string   `yaml:"name"`
		Command string   `yaml:"command"`
		Args    []string `yaml:"args"`
		Env     []string `yaml:"env"`
	} `yaml:"mcp_servers"`
	RateLimit struct {
		RequestsPerSecond int `yaml:"requests_per_second"`
	} `yaml:"rate_limit"`
	CVESources []shared.CVESourceConfig `yaml:"cveSources"`
}

func loadConfig(path string) (shared.CrusadeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return shared.CrusadeConfig{}, fmt.Errorf("cannot read config file: %w", err)
	}

	var raw CrusadeConfigFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return shared.CrusadeConfig{}, fmt.Errorf("invalid YAML: %w", err)
	}

	// Validate required fields.
	var errs []string
	if raw.TargetURL == "" {
		errs = append(errs, "target_url is required")
	}
	if len(raw.AllowedDomains) == 0 {
		errs = append(errs, "allowed_domains must contain at least one entry")
	}
	if raw.OutputDir == "" {
		errs = append(errs, "output_dir is required")
	}
	hasProvider := false
	for _, p := range raw.AIProviders {
		if p.APIKey != "" {
			hasProvider = true
			break
		}
	}
	if !hasProvider {
		errs = append(errs, "at least one ai_providers entry with a non-empty api_key is required")
	}

	// Validate CVESources
	for _, src := range raw.CVESources {
		if !src.Enabled {
			continue
		}
		switch src.Name {
		case shared.CVESourceTypeHackerOne:
			if src.HackerOneAPIKey == "" {
				errs = append(errs, "hackerone source requires hackeroneApiKey")
			}
			if src.HackerOneProgramHandle == "" {
				errs = append(errs, "hackerone source requires hackeroneProgramHandle")
			}
		case shared.CVESourceTypeCustomFeed:
			if src.FeedURL == "" {
				errs = append(errs, "custom_feed source requires feedUrl")
			}
			if src.FeedFormat == "" {
				errs = append(errs, "custom_feed source requires feedFormat")
			}
		}
	}

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  config error: %s\n", e)
		}
		return shared.CrusadeConfig{}, fmt.Errorf("config validation failed with %d error(s)", len(errs))
	}

	providers := make([]shared.AIProviderConfig, len(raw.AIProviders))
	for i, p := range raw.AIProviders {
		// Expand ${ENV_VAR} references in api_key.
		apiKey := p.APIKey
		if len(apiKey) > 2 && apiKey[0] == '$' && apiKey[1] == '{' && apiKey[len(apiKey)-1] == '}' {
			envName := apiKey[2 : len(apiKey)-1]
			if val := os.Getenv(envName); val != "" {
				apiKey = val
			}
		}
		providers[i] = shared.AIProviderConfig{
			Name:        p.Name,
			APIKey:      apiKey,
			Role:        p.Role,
			MaxTokens:   p.MaxTokens,
			Temperature: p.Temperature,
		}
	}

	mcpServers := make([]shared.MCPServerConfig, len(raw.MCPServers))
	for i, s := range raw.MCPServers {
		mcpServers[i] = shared.MCPServerConfig{
			Name:    s.Name,
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
		}
	}

	expandEnv := func(val string) string {
		if len(val) > 2 && val[0] == '$' && val[1] == '{' && val[len(val)-1] == '}' {
			if envVal := os.Getenv(val[2 : len(val)-1]); envVal != "" {
				return envVal
			}
		}
		return val
	}

	cveSources := make([]shared.CVESourceConfig, len(raw.CVESources))
	for i, s := range raw.CVESources {
		cveSources[i] = s
		cveSources[i].HackerOneAPIKey = expandEnv(s.HackerOneAPIKey)
		cveSources[i].GitHubToken = expandEnv(s.GitHubToken)
		if s.FeedAuth != nil {
			cveSources[i].FeedAuth.Token = expandEnv(s.FeedAuth.Token)
			cveSources[i].FeedAuth.APIKey = expandEnv(s.FeedAuth.APIKey)
			cveSources[i].FeedAuth.Password = expandEnv(s.FeedAuth.Password)
		}
	}

	return shared.CrusadeConfig{
		TargetURL:      raw.TargetURL,
		AllowedDomains: raw.AllowedDomains,
		ScanDepth:      shared.ScanDepth(raw.ScanDepth),
		OutputDir:      raw.OutputDir,
		AIProviders:    providers,
		MCPServers:     mcpServers,
		CVESources:     cveSources,
		Scope: shared.ScopeConfig{
			AllowedDomains: raw.AllowedDomains,
			ExcludedPaths:  raw.ExcludedPaths,
		},
		RateLimit: shared.RateLimitConfig{
			RequestsPerSecond: raw.RateLimit.RequestsPerSecond,
		},
	}, nil
}

// ── Authorization gate ────────────────────────────────────────────────────────

func confirmAuthorization(targetURL string, allowedDomains []string, scanDepth string) bool {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          ⚔  TEMPLAR — LEGAL AUTHORIZATION REQUIRED  ⚔       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Target URL   : %s\n", targetURL)
	fmt.Printf("  Allowed scope: %s\n", strings.Join(allowedDomains, ", "))
	fmt.Printf("  Scan depth   : %s\n", scanDepth)
	fmt.Println()
	fmt.Println("  You MUST have explicit written authorisation to test the above target.")
	fmt.Println("  Unauthorised scanning is illegal and may result in criminal prosecution.")
	fmt.Println()
	fmt.Print("  Type 'yes' to confirm you are authorised, or anything else to cancel: ")

	scanner := bufio.NewScanner(os.Stdin)
	done := make(chan string, 1)
	go func() {
		if scanner.Scan() {
			done <- strings.TrimSpace(scanner.Text())
		} else {
			done <- ""
		}
	}()

	select {
	case answer := <-done:
		return strings.EqualFold(answer, "yes") || strings.EqualFold(answer, "y")
	case <-time.After(60 * time.Second):
		fmt.Println("\n  Timeout — authorization not confirmed.")
		return false
	}
}

// ── Progress streaming ────────────────────────────────────────────────────────

// streamDashboard reads from the global event bus and a ticker to print a live dashboard.
// The phase status line is printed in-place (overwriting itself with \r) while
// new unique findings scroll below it.
func streamDashboard(gm *grandmaster.GrandMaster, done <-chan struct{}) {
	var events <-chan shared.CampaignEvent
	if shared.GlobalBus != nil {
		events = shared.GlobalBus.Subscribe()
	} else {
		// Create a dummy channel that never yields
		dummy := make(chan shared.CampaignEvent)
		events = dummy
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	lastStatusLine := ""
	lastPhaseLen := 0

	clearPhaseLine := func() {
		if lastPhaseLen > 0 {
			fmt.Printf("\r%s\r", strings.Repeat(" ", lastPhaseLen))
		}
	}

	printStatus := func() {
		elapsed := time.Since(start).Round(time.Second)
		phases := gm.State.GetPhasesStatus()
		active := "initializing"
		for _, phase := range []string{"preceptor", "hospitaller", "marshal", "chaplain", "scribe"} {
			if s, ok := phases[phase]; ok && s == "running" {
				active = strings.ToUpper(phase)
				break
			}
		}
		status := fmt.Sprintf("  ⏱  [%s]  Phase: %-12s | %s", elapsed, active, gm.GetStatus())
		lastStatusLine = fmt.Sprintf("\r%-80s", status)
		lastPhaseLen = 80
		fmt.Print(lastStatusLine)
	}

	// Print initial status
	printStatus()

	for {
		select {
		case <-done:
			clearPhaseLine()
			fmt.Println() // newline after last status
			return
		case ev, ok := <-events:
			if !ok {
				events = make(chan shared.CampaignEvent) // Never yield again
				continue
			}
			clearPhaseLine()
			fmt.Println(shared.FormatEvent(ev))
			fmt.Print(lastStatusLine)
		case <-ticker.C:
			printStatus()
		}
	}
}

// ── Root command ──────────────────────────────────────────────────────────────

func main() {
	root := &cobra.Command{
		Use:   "templar",
		Short: "Templar — AI-powered offensive security framework",
		Long: `Templar orchestrates reconnaissance, vulnerability analysis, PoC generation,
attack chain synthesis, and comprehensive reporting — starting from a single URL.`,
	}

	root.AddCommand(buildCrusadeCmd())
	root.AddCommand(buildStatusCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── crusade command group ─────────────────────────────────────────────────────

func buildCrusadeCmd() *cobra.Command {
	crusade := &cobra.Command{
		Use:   "crusade",
		Short: "Campaign management commands",
	}
	crusade.AddCommand(buildStartCmd())
	crusade.AddCommand(buildPauseCmd())
	crusade.AddCommand(buildResumeCmd())
	crusade.AddCommand(buildAbortCmd())
	crusade.AddCommand(buildCrusadeStatusCmd())
	return crusade
}

// crusade start ───────────────────────────────────────────────────────────────

func buildStartCmd() *cobra.Command {
	var configPath string
	var allowDestructive bool

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a new Crusade campaign",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return fmt.Errorf("--config is required")
			}

			cfg, err := loadConfig(configPath)
			if err != nil {
				os.Exit(2)
			}

			// Authorization gate.
			if !confirmAuthorization(cfg.TargetURL, cfg.Scope.AllowedDomains, string(cfg.ScanDepth)) {
				fmt.Println("\n  Campaign cancelled — authorization not confirmed.")
				os.Exit(1)
			}
			fmt.Println("\n  Authorization confirmed. Initiating Crusade...")

			gm, err := grandmaster.NewGrandMaster("templar.db", cfg)
			if err != nil {
				if strings.Contains(err.Error(), "DUPLICATE_CAMPAIGN") {
					fmt.Fprintf(os.Stderr, "A campaign for this target is already active\n")
					os.Exit(3)
				}
				return fmt.Errorf("failed to initialize Grand Master: %w", err)
			}
			_ = allowDestructive // passed into config when ModuleFlags is used

			campaignID := uuid.New().String()
			doneCh := make(chan struct{})
			// Start event-driven display (findings scroll) and ticker (phase status line).
			go streamDashboard(gm, doneCh)

			result, err := gm.StartCrusade(campaignID)
			close(doneCh)
			// Close the event bus so streamEvents drains and exits cleanly.
			if shared.GlobalBus != nil {
				shared.GlobalBus.Close()
			}
			fmt.Println()

			if err != nil {
				log.Printf("Crusade error: %v", err)
			}

			if result != nil {
				printCompletionSummary(result, cfg.OutputDir)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to YAML campaign config file (required)")
	cmd.Flags().BoolVar(&allowDestructive, "allow-destructive", false, "Allow validation of destructive PoCs")
	return cmd
}

// crusade pause ───────────────────────────────────────────────────────────────

func buildPauseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pause <campaignId>",
		Short: "Pause a running campaign",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Pause requested for campaign %s\n", args[0])
			fmt.Println("(Use the in-process API or re-attach to a running session to pause.)")
			return nil
		},
	}
}

// crusade resume ──────────────────────────────────────────────────────────────

func buildResumeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resume <campaignId>",
		Short: "Resume a paused campaign",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Resume requested for campaign %s\n", args[0])
			fmt.Println("(Use the in-process API or re-attach to a running session to resume.)")
			return nil
		},
	}
}

// crusade abort ───────────────────────────────────────────────────────────────

func buildAbortCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "abort <campaignId>",
		Short: "Abort a running or paused campaign",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Abort requested for campaign %s\n", args[0])
			fmt.Println("(Use the in-process API or re-attach to a running session to abort.)")
			return nil
		},
	}
}

// crusade status ──────────────────────────────────────────────────────────────

func buildCrusadeStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <campaignId>",
		Short: "Show campaign status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Status for campaign %s: use --config and reattach to query live status.\n", args[0])
			return nil
		},
	}
}

// top-level status shortcut ───────────────────────────────────────────────────

func buildStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show framework status",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Templar v1.0.0 — ready. Use 'templar crusade start --config <file>' to begin.")
		},
	}
}

// ── Completion summary ────────────────────────────────────────────────────────

func printCompletionSummary(result *shared.CampaignResult, outputDir string) {
	sevCounts := map[string]int{}
	for _, v := range result.Vulnerabilities {
		sevCounts[strings.ToLower(v.Severity)]++
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  ⚔  CRUSADE COMPLETE  ⚔                      ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Printf("  Campaign ID  : %s\n", result.CampaignID)
	fmt.Printf("  Output dir   : %s\n", outputDir)
	fmt.Println()
	fmt.Println("  Vulnerabilities:")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := sevCounts[sev]; n > 0 {
			fmt.Printf("    %-10s %d\n", strings.Title(sev)+":", n)
		}
	}
	fmt.Printf("\n  Attack Chains : %d\n", len(result.AttackChains))
	fmt.Printf("  PoCs          : %d\n", len(result.PoCs))
	fmt.Println()
	fmt.Println("  Reports written to: " + outputDir)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}
