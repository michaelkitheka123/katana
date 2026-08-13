package relichunter

import (
	"testing"

	"github.com/templar-framework/templar/internal/shared"
)

func TestValidateSourceConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     shared.CVESourceConfig
		wantErr bool
	}{
		{
			name: "Valid HackerOne",
			cfg: shared.CVESourceConfig{
				Name:                   shared.CVESourceTypeHackerOne,
				Enabled:                true,
				HackerOneAPIKey:        "key",
				HackerOneProgramHandle: "prog",
			},
			wantErr: false,
		},
		{
			name: "Invalid HackerOne missing handle",
			cfg: shared.CVESourceConfig{
				Name:            shared.CVESourceTypeHackerOne,
				Enabled:         true,
				HackerOneAPIKey: "key",
			},
			wantErr: true,
		},
		{
			name: "Valid GitHub",
			cfg: shared.CVESourceConfig{
				Name:        shared.CVESourceTypeGitHub,
				Enabled:     true,
				GitHubToken: "token",
			},
			wantErr: false,
		},
		{
			name: "Invalid GitHub missing token",
			cfg: shared.CVESourceConfig{
				Name:    shared.CVESourceTypeGitHub,
				Enabled: true,
			},
			wantErr: true,
		},
		{
			name: "Valid CustomFeed",
			cfg: shared.CVESourceConfig{
				Name:    shared.CVESourceTypeCustomFeed,
				Enabled: true,
				FeedURL: "http://example.com/feed",
			},
			wantErr: false,
		},
		{
			name: "Invalid CustomFeed missing URL",
			cfg: shared.CVESourceConfig{
				Name:    shared.CVESourceTypeCustomFeed,
				Enabled: true,
			},
			wantErr: true,
		},
		{
			name: "Disabled skips validation",
			cfg: shared.CVESourceConfig{
				Name:    shared.CVESourceTypeGitHub,
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "Negative timeout",
			cfg: shared.CVESourceConfig{
				Name:           shared.CVESourceTypeNVD,
				Enabled:        true,
				TimeoutSeconds: -1,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSourceConfig(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSourceConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
