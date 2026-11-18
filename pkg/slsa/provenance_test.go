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
	"strings"
	"testing"
)

const slsa02Statement = `{
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"subject": [
		{"name": "example.com/app", "digest": {"sha256": "abc123"}}
	],
	"predicate": {
		"builder": {"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.9.0"},
		"buildType": "https://github.com/slsa-framework/slsa-github-generator/go@v1",
		"invocation": {},
		"materials": [
			{"uri": "git+https://github.com/example/app", "digest": {"sha1": "deadbeef"}},
			{"uri": "pkg:docker/golang@1.21", "digest": {"sha256": "cafe"}}
		]
	}
}`

const slsa1Statement = `{
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v1",
	"subject": [
		{"name": "example.com/app", "digest": {"sha256": "abc123"}}
	],
	"predicate": {
		"buildDefinition": {
			"buildType": "https://github.com/slsa-framework/slsa-github-generator/go@v1",
			"externalParameters": {},
			"resolvedDependencies": [
				{"uri": "git+https://github.com/example/app", "digest": {"gitCommit": "deadbeef"}},
				{"uri": "pkg:docker/golang@1.21", "digest": {"sha256": "cafe"}}
			]
		},
		"runDetails": {
			"builder": {"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.9.0"}
		}
	}
}`

const slsa01Statement = `{
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://slsa.dev/provenance/v0.1",
	"subject": [
		{"name": "example.com/app", "digest": {"sha256": "abc123"}}
	],
	"predicate": {
		"builder": {"id": "https://github.com/Attestations/GitHubHostedActions@v1"},
		"recipe": {"type": "https://github.com/Attestations/GitHubActionsWorkflow@v1"},
		"materials": [
			{"uri": "git+https://github.com/example/app", "digest": {"sha1": "deadbeef"}}
		]
	}
}`

func TestParseProvenance(t *testing.T) {
	tests := []struct {
		name          string
		statement     string
		wantPredicate string
		wantBuilder   string
		wantBuildType string
		wantMaterials int
	}{{
		name:          "slsa v0.2",
		statement:     slsa02Statement,
		wantPredicate: "https://slsa.dev/provenance/v0.2",
		wantBuilder:   "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.9.0",
		wantBuildType: "https://github.com/slsa-framework/slsa-github-generator/go@v1",
		wantMaterials: 2,
	}, {
		name:          "slsa v1",
		statement:     slsa1Statement,
		wantPredicate: "https://slsa.dev/provenance/v1",
		wantBuilder:   "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.9.0",
		wantBuildType: "https://github.com/slsa-framework/slsa-github-generator/go@v1",
		wantMaterials: 2,
	}, {
		name:          "slsa v0.1",
		statement:     slsa01Statement,
		wantPredicate: "https://slsa.dev/provenance/v0.1",
		wantBuilder:   "https://github.com/Attestations/GitHubHostedActions@v1",
		wantBuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		wantMaterials: 1,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prov, err := ParseProvenance([]byte(tc.statement))
			if err != nil {
				t.Fatalf("ParseProvenance() error = %v", err)
			}
			if prov.PredicateType != tc.wantPredicate {
				t.Errorf("PredicateType = %q, want %q", prov.PredicateType, tc.wantPredicate)
			}
			if prov.BuilderID != tc.wantBuilder {
				t.Errorf("BuilderID = %q, want %q", prov.BuilderID, tc.wantBuilder)
			}
			if prov.BuildType != tc.wantBuildType {
				t.Errorf("BuildType = %q, want %q", prov.BuildType, tc.wantBuildType)
			}
			if len(prov.Materials) != tc.wantMaterials {
				t.Fatalf("len(Materials) = %d, want %d", len(prov.Materials), tc.wantMaterials)
			}
			if len(prov.Subject) != 1 || prov.Subject[0].Name != "example.com/app" {
				t.Errorf("unexpected subject: %+v", prov.Subject)
			}
		})
	}
}

func TestParseProvenanceSLSA1Materials(t *testing.T) {
	prov, err := ParseProvenance([]byte(slsa1Statement))
	if err != nil {
		t.Fatalf("ParseProvenance() error = %v", err)
	}
	// resolvedDependencies must be exposed as materials.
	if prov.Materials[0].URI != "git+https://github.com/example/app" {
		t.Errorf("Materials[0].URI = %q", prov.Materials[0].URI)
	}
	if prov.Materials[0].Digest["gitCommit"] != "deadbeef" {
		t.Errorf("Materials[0].Digest = %v", prov.Materials[0].Digest)
	}
}

func TestParseProvenanceErrors(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		wantErr   string
	}{{
		name:      "invalid json",
		statement: `{not json`,
		wantErr:   "unmarshaling in-toto statement",
	}, {
		name:      "wrong statement type",
		statement: `{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1"}`,
		wantErr:   "unsupported statement type",
	}, {
		name:      "not a slsa predicate",
		statement: `{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://spdx.dev/Document"}`,
		wantErr:   "not a SLSA provenance statement",
	}, {
		name:      "malformed predicate",
		statement: `{"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://slsa.dev/provenance/v0.2", "predicate": "nope"}`,
		wantErr:   "unmarshaling SLSA v0.2 provenance",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProvenance([]byte(tc.statement))
			if err == nil {
				t.Fatal("ParseProvenance() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}
