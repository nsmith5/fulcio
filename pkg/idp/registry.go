package idp

import (
	"crypto/x509"
	"errors"
)

var (
	ErrNotImplemented     = errors.New(`Not implemented`)
	ErrNoMatchingProvider = errors.New(`No identity providers match for this token`)
)

// Registry stores a set of identity providers and matches
// identity tokens to the provider
type Registry struct {
}

// Register an identity provider with the registry
func (r *Registry) Register(conf Config) error {
	return ErrNotImplemented
}

// Match finds an appropriate identity provider for an id token
// if possible or errors if none match
func (r *Registry) Match(token string) (Provider, error) {
	return nil, ErrNoMatchingProvider
}

// Config is the configuration of an identity provider
type Config struct {
	IssuerURL   string `json:"IssuerURL,omitempty"`
	ClientID    string `json:"ClientID"`
	Type        string `json:"Type"`
	IssuerClaim string `json:"IssuerClaim,omitempty"`
}

// Provider can verify tokens with a challenge and returns a function to modify
// x509 certificates appropriately on success.
type Provider interface {
	Challenge(token string) (CertificateFunc, error)
}

// CertificateFunc modifies an x509 certificate to add the information
// from a successful identity provider challenge
type CertificateFunc func(x509.Certificate) x509.Certificate
