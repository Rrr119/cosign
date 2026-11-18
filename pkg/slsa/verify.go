//
// Copyright 2026 The Sigstore Authors.
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

package slsa

import (
	"fmt"
	"slices"
	"strings"
)

// VerifyOptions describes the supply-chain policy a SLSA provenance
// statement is verified against.
type VerifyOptions struct {
	// TrustedBuilderIDs is the set of builder identities accepted by the
	// consumer. If empty, the builder is not checked.
	TrustedBuilderIDs []string
	// RequiredMaterials lists materials that must be present in the
	// provenance. A material matches by URI; any digest entries given here
	// must also match the digests recorded in the provenance.
	RequiredMaterials []Material
}

// VerificationError reports every reason a provenance failed verification,
// so that callers can surface all problems at once instead of one at a time.
type VerificationError struct {
	Reasons []string
}

// Error implements the error interface.
func (e *VerificationError) Error() string {
	return fmt.Sprintf("SLSA provenance verification failed: %s", strings.Join(e.Reasons, "; "))
}

// Verify checks the provenance against the given options. It returns nil if
// the provenance satisfies the policy, or a *VerificationError describing
// every check that failed.
func Verify(prov *Provenance, opts VerifyOptions) error {
	if prov == nil {
		return &VerificationError{Reasons: []string{"no provenance provided"}}
	}

	var reasons []string

	if len(opts.TrustedBuilderIDs) > 0 {
		switch {
		case prov.BuilderID == "":
			reasons = append(reasons, "provenance does not identify a builder")
		case !slices.Contains(opts.TrustedBuilderIDs, prov.BuilderID):
			reasons = append(reasons, fmt.Sprintf("builder %q is not trusted (trusted builders: %s)",
				prov.BuilderID, strings.Join(opts.TrustedBuilderIDs, ", ")))
		}
	}

	for _, required := range opts.RequiredMaterials {
		reasons = append(reasons, verifyMaterial(prov.Materials, required)...)
	}

	if len(reasons) > 0 {
		return &VerificationError{Reasons: reasons}
	}
	return nil
}

// verifyMaterial checks a single required material against the materials
// recorded in the provenance, returning a reason for every mismatch.
func verifyMaterial(materials []Material, required Material) []string {
	if required.URI == "" {
		return []string{"required material has an empty URI"}
	}

	var matched *Material
	for i := range materials {
		if materials[i].URI == required.URI {
			matched = &materials[i]
			break
		}
	}
	if matched == nil {
		return []string{fmt.Sprintf("required material %q is not present in the provenance", required.URI)}
	}

	var reasons []string
	for alg, want := range required.Digest {
		got, ok := matched.Digest[alg]
		switch {
		case !ok:
			reasons = append(reasons, fmt.Sprintf("material %q has no %s digest in the provenance", required.URI, alg))
		case !strings.EqualFold(got, want):
			reasons = append(reasons, fmt.Sprintf("material %q digest mismatch: expected %s=%s, got %s=%s",
				required.URI, alg, want, alg, got))
		}
	}
	return reasons
}
