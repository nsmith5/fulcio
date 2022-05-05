package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type IssuerPool []Issuer

func (p IssuerPool) Authenticate(ctx context.Context, token string) (Principal, error) {
	url, err := extractIssuerURL(token)
	if err != nil {
		return nil, err
	}

	for _, issuer := range p {
		if issuer.Match(ctx, url) {
			return issuer.Authenticate(ctx, token)
		}
	}
	return nil, fmt.Errorf("Failed to match issuer URL %s from token with any configured providers", url)
}

func extractIssuerURL(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidc: malformed jwt payload: %w", err)
	}

	var payload struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("oidc: failed to unmarshal claims: %w", err)
	}
	return payload.Issuer, nil
}
