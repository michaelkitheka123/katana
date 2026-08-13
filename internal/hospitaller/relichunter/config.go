package relichunter

import (
	"fmt"

	"github.com/templar-framework/templar/internal/shared"
)

// ValidateSourceConfig validates a single CVESourceConfig.
func ValidateSourceConfig(cfg shared.CVESourceConfig) error {
	if !cfg.Enabled {
		return nil
	}

	switch cfg.Name {
	case shared.CVESourceTypeHackerOne:
		if cfg.HackerOneAPIKey == "" {
			return fmt.Errorf("HackerOne source requires HackerOneAPIKey")
		}
		if cfg.HackerOneProgramHandle == "" {
			return fmt.Errorf("HackerOne source requires HackerOneProgramHandle")
		}
	case shared.CVESourceTypeGitHub:
		if cfg.GitHubToken == "" {
			return fmt.Errorf("GitHub source requires GitHubToken for GraphQL API")
		}
	case shared.CVESourceTypeCustomFeed:
		if cfg.FeedURL == "" {
			return fmt.Errorf("CustomFeed source requires FeedURL")
		}
	}

	if cfg.TimeoutSeconds < 0 {
		return fmt.Errorf("TimeoutSeconds cannot be negative")
	}

	return nil
}

// ValidateAllSourceConfigs validates an array of configs.
func ValidateAllSourceConfigs(configs []shared.CVESourceConfig) error {
	for _, cfg := range configs {
		if err := ValidateSourceConfig(cfg); err != nil {
			return fmt.Errorf("invalid config for source %s: %w", cfg.Name, err)
		}
	}
	return nil
}
