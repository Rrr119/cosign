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

// Package slsa provides parsing and verification of SLSA provenance
// predicates carried by in-toto statements.
package slsa

import (
	"encoding/json"
	"fmt"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
)

// Material identifies an artifact that influenced the build.
type Material = common.ProvenanceMaterial

// DigestSet contains a set of digests, keyed by algorithm name.
type DigestSet = common.DigestSet

// Subject describes a software artifact the statement applies to.
type Subject = in_toto.Subject

// Provenance is a normalized view of a SLSA provenance predicate,
// independent of the SLSA version (v0.1, v0.2 and v1 are supported).
type Provenance struct {
	// PredicateType is the URI of the SLSA provenance predicate type.
	PredicateType string
	// BuilderID identifies the entity that executed the build.
	BuilderID string
	// BuildType is a URI indicating what type of build was performed.
	BuildType string
	// Materials is the collection of artifacts that influenced the build.
	// For SLSA v1 this maps to buildDefinition.resolvedDependencies.
	Materials []Material
	// Subject is the set of artifacts the statement applies to.
	Subject []Subject
}

// ParseProvenance parses an in-toto statement carrying a SLSA provenance
// predicate (v0.1, v0.2 or v1) into a normalized Provenance.
func ParseProvenance(data []byte) (*Provenance, error) {
	var header in_toto.StatementHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("unmarshaling in-toto statement: %w", err)
	}
	if header.Type != in_toto.StatementInTotoV01 {
		return nil, fmt.Errorf("unsupported statement type %q, expected %q", header.Type, in_toto.StatementInTotoV01)
	}

	switch header.PredicateType {
	case slsa01.PredicateSLSAProvenance:
		var statement in_toto.ProvenanceStatementSLSA01
		if err := json.Unmarshal(data, &statement); err != nil {
			return nil, fmt.Errorf("unmarshaling SLSA v0.1 provenance: %w", err)
		}
		return &Provenance{
			PredicateType: statement.PredicateType,
			BuilderID:     statement.Predicate.Builder.ID,
			BuildType:     statement.Predicate.Recipe.Type,
			Materials:     statement.Predicate.Materials,
			Subject:       statement.Subject,
		}, nil
	case slsa02.PredicateSLSAProvenance:
		var statement in_toto.ProvenanceStatementSLSA02
		if err := json.Unmarshal(data, &statement); err != nil {
			return nil, fmt.Errorf("unmarshaling SLSA v0.2 provenance: %w", err)
		}
		return &Provenance{
			PredicateType: statement.PredicateType,
			BuilderID:     statement.Predicate.Builder.ID,
			BuildType:     statement.Predicate.BuildType,
			Materials:     statement.Predicate.Materials,
			Subject:       statement.Subject,
		}, nil
	case slsa1.PredicateSLSAProvenance:
		var statement in_toto.ProvenanceStatementSLSA1
		if err := json.Unmarshal(data, &statement); err != nil {
			return nil, fmt.Errorf("unmarshaling SLSA v1 provenance: %w", err)
		}
		materials := make([]Material, 0, len(statement.Predicate.BuildDefinition.ResolvedDependencies))
		for _, dep := range statement.Predicate.BuildDefinition.ResolvedDependencies {
			materials = append(materials, Material{
				URI:    dep.URI,
				Digest: dep.Digest,
			})
		}
		return &Provenance{
			PredicateType: statement.PredicateType,
			BuilderID:     statement.Predicate.RunDetails.Builder.ID,
			BuildType:     statement.Predicate.BuildDefinition.BuildType,
			Materials:     materials,
			Subject:       statement.Subject,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported predicate type %q: not a SLSA provenance statement", header.PredicateType)
	}
}
