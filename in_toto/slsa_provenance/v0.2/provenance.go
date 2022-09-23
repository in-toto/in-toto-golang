package v02

import (
	"time"

	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

const (
	// PredicateSLSAProvenance represents a build provenance for an artifact.
	PredicateSLSAProvenance = "https://slsa.dev/provenance/v0.2"
)

// ProvenancePredicate is the provenance predicate definition.
type ProvenancePredicate struct {
	Builder     common.ProvenanceBuilder    `json:"builder"`
	BuildType   string                      `json:"buildType"`
	Invocation  ProvenanceInvocation        `json:"invocation,omitempty"`
	BuildConfig interface{}                 `json:"buildConfig,omitempty"`
	Metadata    *ProvenanceMetadata         `json:"metadata,omitempty"`
	Materials   []common.ProvenanceMaterial `json:"materials,omitempty"`
}

// ProvenanceInvocation identifies the event that kicked off the build.
type ProvenanceInvocation struct {
	ConfigSource ConfigSource `json:"configSource,omitempty"`
	Parameters   interface{}  `json:"parameters,omitempty"`
	Environment  interface{}  `json:"environment,omitempty"`
}

type ConfigSource struct {
	URI        string           `json:"uri,omitempty"`
	Digest     common.DigestSet `json:"digest,omitempty"`
	EntryPoint string           `json:"entryPoint,omitempty"`
}

// ProvenanceMetadata contains metadata for the built artifact.
type ProvenanceMetadata struct {
	BuildInvocationID string `json:"buildInvocationID,omitempty"`
	// Use pointer to make sure that the abscense of a time is not
	// encoded as the Epoch time.
	BuildStartedOn  *time.Time         `json:"buildStartedOn,omitempty"`
	BuildFinishedOn *time.Time         `json:"buildFinishedOn,omitempty"`
	Completeness    ProvenanceComplete `json:"completeness"`
	Reproducible    bool               `json:"reproducible"`
}

// ProvenanceComplete indicates wheter the claims in build/recipe are complete.
// For in depth information refer to the specifictaion:
// https://github.com/in-toto/attestation/blob/v0.1.0/spec/predicates/provenance.md
type ProvenanceComplete struct {
	Parameters  bool `json:"parameters"`
	Environment bool `json:"environment"`
	Materials   bool `json:"materials"`
}
