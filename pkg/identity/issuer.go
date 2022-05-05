package identity

import "context"

type Issuer interface {
	// Can this Issuer authenticate the given issuer URL?
	Match(ctx context.Context, url string) bool

	// Authenticate ID token and return Principal on success
	Authenticate(ctx context.Context, token string) (Principal, error)
}
