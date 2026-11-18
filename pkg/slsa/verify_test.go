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
	"errors"
	"strings"
	"testing"
)

const trustedBuilder = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.9.0"

func testProvenance(t *testing.T) *Provenance {
	t.Helper()
	prov, err := ParseProvenance([]byte(slsa02Statement))
	if err != nil {
		t.Fatalf("ParseProvenance() error = %v", err)
	}
	return prov
}

func TestVerifySuccess(t *testing.T) {
	prov := testProvenance(t)
	err := Verify(prov, VerifyOptions{
		TrustedBuilderIDs: []string{trustedBuilder},
		RequiredMaterials: []Material{
			{URI: "git+https://github.com/example/app", Digest: DigestSet{"sha1": "deadbeef"}},
			{URI: "pkg:docker/golang@1.21"},
		},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyNoOptions(t *testing.T) {
	if err := Verify(testProvenance(t), VerifyOptions{}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyNilProvenance(t *testing.T) {
	err := Verify(nil, VerifyOptions{})
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("Verify() error = %v, want *VerificationError", err)
	}
	if !strings.Contains(err.Error(), "no provenance provided") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyBuilder(t *testing.T) {
	prov := testProvenance(t)

	t.Run("untrusted builder", func(t *testing.T) {
		err := Verify(prov, VerifyOptions{TrustedBuilderIDs: []string{"https://example.com/trusted-builder"}})
		var verr *VerificationError
		if !errors.As(err, &verr) {
			t.Fatalf("Verify() error = %v, want *VerificationError", err)
		}
		if len(verr.Reasons) != 1 {
			t.Fatalf("got %d reasons, want 1: %v", len(verr.Reasons), verr.Reasons)
		}
		if !strings.Contains(verr.Reasons[0], "is not trusted") {
			t.Errorf("unexpected reason: %q", verr.Reasons[0])
		}
		// The untrusted and trusted builder IDs must appear in the message.
		if !strings.Contains(err.Error(), trustedBuilder) || !strings.Contains(err.Error(), "https://example.com/trusted-builder") {
			t.Errorf("error message missing builder IDs: %v", err)
		}
	})

	t.Run("missing builder", func(t *testing.T) {
		prov := *prov
		prov.BuilderID = ""
		err := Verify(&prov, VerifyOptions{TrustedBuilderIDs: []string{trustedBuilder}})
		if err == nil || !strings.Contains(err.Error(), "does not identify a builder") {
			t.Errorf("Verify() error = %v", err)
		}
	})
}

func TestVerifyMaterials(t *testing.T) {
	prov := testProvenance(t)

	t.Run("missing material", func(t *testing.T) {
		err := Verify(prov, VerifyOptions{
			RequiredMaterials: []Material{{URI: "git+https://github.com/example/other"}},
		})
		if err == nil || !strings.Contains(err.Error(), `required material "git+https://github.com/example/other" is not present`) {
			t.Errorf("Verify() error = %v", err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		err := Verify(prov, VerifyOptions{
			RequiredMaterials: []Material{{URI: "git+https://github.com/example/app", Digest: DigestSet{"sha1": "beefdead"}}},
		})
		if err == nil || !strings.Contains(err.Error(), "expected sha1=beefdead, got sha1=deadbeef") {
			t.Errorf("Verify() error = %v", err)
		}
	})

	t.Run("digest algorithm absent", func(t *testing.T) {
		err := Verify(prov, VerifyOptions{
			RequiredMaterials: []Material{{URI: "git+https://github.com/example/app", Digest: DigestSet{"sha512": "00"}}},
		})
		if err == nil || !strings.Contains(err.Error(), "has no sha512 digest") {
			t.Errorf("Verify() error = %v", err)
		}
	})

	t.Run("digest case insensitive", func(t *testing.T) {
		err := Verify(prov, VerifyOptions{
			RequiredMaterials: []Material{{URI: "git+https://github.com/example/app", Digest: DigestSet{"sha1": "DEADBEEF"}}},
		})
		if err != nil {
			t.Errorf("Verify() error = %v", err)
		}
	})

	t.Run("empty uri", func(t *testing.T) {
		err := Verify(prov, VerifyOptions{
			RequiredMaterials: []Material{{Digest: DigestSet{"sha1": "deadbeef"}}},
		})
		if err == nil || !strings.Contains(err.Error(), "empty URI") {
			t.Errorf("Verify() error = %v", err)
		}
	})
}

func TestVerifyAggregatesReasons(t *testing.T) {
	prov := testProvenance(t)
	err := Verify(prov, VerifyOptions{
		TrustedBuilderIDs: []string{"https://example.com/other-builder"},
		RequiredMaterials: []Material{
			{URI: "git+https://github.com/example/missing"},
			{URI: "pkg:docker/golang@1.21", Digest: DigestSet{"sha256": "wrong"}},
		},
	})
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("Verify() error = %v, want *VerificationError", err)
	}
	if len(verr.Reasons) != 3 {
		t.Fatalf("got %d reasons, want 3: %v", len(verr.Reasons), verr.Reasons)
	}
	// All reasons must be surfaced in a single message.
	msg := err.Error()
	for _, substr := range []string{"is not trusted", "is not present", "digest mismatch"} {
		if !strings.Contains(msg, substr) {
			t.Errorf("error message %q missing %q", msg, substr)
		}
	}
}

func TestVerifySLSA1(t *testing.T) {
	prov, err := ParseProvenance([]byte(slsa1Statement))
	if err != nil {
		t.Fatalf("ParseProvenance() error = %v", err)
	}
	err = Verify(prov, VerifyOptions{
		TrustedBuilderIDs: []string{trustedBuilder},
		RequiredMaterials: []Material{
			{URI: "git+https://github.com/example/app", Digest: DigestSet{"gitCommit": "deadbeef"}},
		},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}
