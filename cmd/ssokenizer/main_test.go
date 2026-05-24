package main

import (
	"strings"
	"testing"

	ssokenizer "github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	xoauth2 "golang.org/x/oauth2"
)

func TestOAuthProviderAuthStyle(t *testing.T) {
	tests := []struct {
		name            string
		authStyle       string
		wantAuthStyle   xoauth2.AuthStyle
		wantErrContains string
	}{
		{
			name:          "omitted leaves library default (auto-detect)",
			authStyle:     "",
			wantAuthStyle: xoauth2.AuthStyleAutoDetect,
		},
		{
			name:          "header explicit",
			authStyle:     "header",
			wantAuthStyle: xoauth2.AuthStyleInHeader,
		},
		{
			name:          "params",
			authStyle:     "params",
			wantAuthStyle: xoauth2.AuthStyleInParams,
		},
		{
			name:            "invalid value returns error",
			authStyle:       "garbage",
			wantErrContains: "auth_style",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ic := &IdentityProviderConfig{
				Profile:      "oauth",
				ClientID:     "x",
				ClientSecret: "y",
				AuthURL:      "http://a",
				TokenURL:     "http://t",
				AuthStyle:    tt.authStyle,
			}

			provider, err := ic.oauthProvider(ssokenizer.ProviderConfig{}, nil)

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrContains)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Fatalf("expected error containing %q, got: %v", tt.wantErrContains, err)
				}
				if !strings.Contains(err.Error(), tt.authStyle) {
					t.Fatalf("expected error to contain the offending value %q, got: %v", tt.authStyle, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			op := provider.(*oauth2.Provider)
			if got := op.OAuthConfig.Endpoint.AuthStyle; got != tt.wantAuthStyle {
				t.Fatalf("AuthStyle: got %v, want %v", got, tt.wantAuthStyle)
			}
		})
	}
}
