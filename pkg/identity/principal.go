package identity

import (
	"context"
	"crypto/x509"
)

type Principal interface {
	// URI, email etc of principal (usually matches `sub` from ID token)
	Name(ctx context.Context) string

	// Embed all SubjectNameAlt and custom x509 extension information into
	// certificate.
	Embed(ctx context.Context, cert x509.Certificate) (x509.Certificate, error)
}
