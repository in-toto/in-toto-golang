package v1

import (
	"time"

	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

const (
	// PredicateSLSAProvenance represents a build provenance for an artifact.
	PredicateSLSAProvenance = "https://slsa.dev/provenance/v1?draft"
)

// ProvenancePredicate is the provenance predicate definition.
type ProvenancePredicate struct {
	// The BuildDefinition describes all of the inputs to the build. The
	// accuracy and completeness are implied by runDetails.builder.id.
	//
	// It SHOULD contain all the information necessary and sufficient to
	// initialize the build and begin execution.
	BuildDefinition ProvenanceBuildDefinition `json:"buildDefinition"`

	// Details specific to this particular execution of the build.
	RunDetails ProvenanaceRunDetails `json:"runDetails"`
}

// ProvenanceBuildDefinition describes the inputs to the build.
type ProvenanceBuildDefinition struct {
	// Identifies the template for how to perform the build and interpret the
	// parameters and dependencies.

	// The URI SHOULD resolve to a human-readable specification that includes:
	// overall description of the build type; schema for externalParameters and
	// systemParameters; unambiguous instructions for how to initiate the build
	// given this BuildDefinition, and a complete example.
	BuildType string `json:"buildType"`

	// The parameters that are under external control, such as those set by a
	// user or tenant of the build system. They MUST be complete at SLSA Build
	// L3, meaning that that there is no additional mechanism for an external
	// party to influence the build. (At lower SLSA Build levels, the
	// completeness MAY be best effort.)

	// The build system SHOULD be designed to minimize the size and complexity
	// of externalParameters, in order to reduce fragility and ease
	// verification. Consumers SHOULD have an expectation of what “good” looks
	// like; the more information that they need to check, the harder that task
	// becomes.
	ExternalParameters interface{} `json:"externalParamaters"`

	// The parameters that are under the control of the builder. The primary
	// intention of this field is for debugging, incident response, and
	// vulnerability management. The values here MAY be necessary for
	// reproducing the build. There is no need to verify these parameters
	// because the build system is already trusted, and in many cases it is not
	// practical to do so.
	SystemParameters interface{} `json:"systemParameters,omitempty"`

	// Unordered collection of artifacts needed at build time. Completeness is
	// best effort, at least through SLSA Build L3. For example, if the build
	// script fetches and executes “example.com/foo.sh”, which in turn fetches
	// “example.com/bar.tar.gz”, then both “foo.sh” and “bar.tar.gz” SHOULD be
	// listed here.
	ResolvedDependencies []ArtifactReference `json:"resolvedDependencies,omitempty"`
}

// ProvenanceRunDetails includes details specific to a particular execution of a
// build.
type ProvenanaceRunDetails struct {
	// Identifies the entity that executed the invocation, which is trusted to
	// have correctly performed the operation and populated this provenance.
	//
	// This field is REQUIRED for SLSA Build 1 unless id is implicit from the
	// attestation envelope.
	Builder Builder `json:"builder"`

	// Metadata about this particular execution of the build.
	BuildMetadata BuildMetadata `json:"metadata,omitempty"`

	// Additional artifacts generated during the build that are not considered
	// the “output” of the build but that might be needed during debugging or
	// incident response. For example, this might reference logs generated
	// during the build and/or a digest of the fully evaluated build
	// configuration.
	//
	// In most cases, this SHOULD NOT contain all intermediate files generated
	// during the build. Instead, this SHOULD only contain files that are
	// likely to be useful later and that cannot be easily reproduced.
	Byproducts []ArtifactReference `json:"byproducts,omitempty"`
}

// ArtifactReference describes a particular artifact. At least one of URI or
// digest MUST be specified.
type ArtifactReference struct {
	// URI describing where this artifact came from. When possible, this SHOULD
	// be a universal and stable identifier, such as a source location or
	// Package URL (purl).
	URI string `json:"uri,omitempty"`

	// One or more cryptographic digests of the contents of this artifact.
	Digest common.DigestSet `json:"digest,omitempty"`

	// The name for this artifact local to the build.
	LocalName string `json:"localName,omitempty"`

	// URI identifying the location that this artifact was downloaded from, if
	// different and not derivable from uri.
	DownloadLocation string `json:"downloadLocation,omitempty"`

	// Media type (aka MIME type) of this artifact was interpreted.
	MediaType string `json:"mediaType,omitempty"`
}

// Builder represents the transitive closure of all the entities that are, by
// necessity, trusted to faithfully run the build and record the provenance.
type Builder struct {
	// URI indicating the transitive closure of the trusted builder.
	ID string `json:"id"`

	// Version numbers of components of the builder.
	Version map[string]string `json:"version,omitempty"`

	// Dependencies used by the orchestrator that are not run within the
	// workload and that do not affect the build, but might affect the
	// provenance generation or security guarantees.
	BuilderDependencies []ArtifactReference `json:"builderDependencies,omitempty"`
}

type BuildMetadata struct {
	// Identifies this particular build invocation, which can be useful for
	// finding associated logs or other ad-hoc analysis. The exact meaning and
	// format is defined by builder.id; by default it is treated as opaque and
	// case-sensitive. The value SHOULD be globally unique.
	InvocationID string `json:"invocationID,omitempty"`

	// The timestamp of when the build started.
	StartedOn *time.Time `json:"startedOn,omitempty"`

	// The timestamp of when the build completed.
	FinishedOn *time.Time `json:"finishedOn,omitempty"`
}
