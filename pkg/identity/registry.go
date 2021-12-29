package identity

import "context"

// ProviderRegistry is a collection of Providers
type ProviderRegistry interface {
	Register(ctx context.Context) error
	Lookup(ctx context.Context, issuerURL string) (Provider, error)
}
