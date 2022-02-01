//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"crypto/x509"
	"errors"
)

// ErrNotAuthenticated is returned on failure to authenicate for any reason
var ErrNotAuthenticated = errors.New(`identity: authenticated failed`)

// Principal is an authenticated identity (GMail user, workload with SPIFFE-ID
// etc).
type Principal interface {
	// Name is the unique identifier for this principal. This must correspond
	// to the `sub` claim in OIDC ID token. It is the email address of human
	// users, the workflow URL for github actions etc...
	Name() string

	// Embed principal specific details into an x509 certificate. This must set
	// the subject name alternative value and can optionally set other
	// extensions with additional information.
	Embed(cert x509.Certificate) x509.Certificate
}

// Issuer is an identity issuer (Google, Github, etc)
type Issuer interface {
	// Match checks if a given issuer url matches this particular identity
	// issuer.
	Match(url string) bool

	// Authenticate identity using identity token. If authenticated, the
	// principal is returned, otherwise ErrNotAuthenticated
	Authenticate(token string) (Principal, error)
}
