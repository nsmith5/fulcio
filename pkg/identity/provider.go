package identity

import (
	"context"
	"crypto/x509"
)

// CertificateMiddleware modifies an x509 certificate
type CertificateMiddleware func(x509.Certificate) x509.Certificate

// Provider abstracts OIDC identity providers
type Provider interface {
	// Authenticate OIDC token
	Authenticate(ctx context.Context, token string) error

	// Challenge validates the certificate signing request challenge (verifies
	// the requester owns the private key).
	Challenge(ctx context.Context) (CertificateMiddleware, error)
}
