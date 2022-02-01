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

import "errors"

// IssuerPool is a collection of identity issuers to authenticate against
type IssuerPool []Issuer

// Authenticate finds a matching issuer in the pool and authenticates with it.
// If bad credentials or no matching issuer, ErrNotAuthenticated is returned.
func (ip IssuerPool) Authenticate(token string) (Principal, error) {
	return nil, errors.New(`identity: not implemented`)
}
