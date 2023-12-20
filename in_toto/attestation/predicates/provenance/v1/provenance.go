package v1

import (
	"fmt"
	"time"

	prov1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	ita1 "github.com/in-toto/attestation/go/v1"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// PredicateSLSAProvenance represents a build provenance for an artifact.
	SLSAProvenancePredicateType = "https://slsa.dev/provenance/v1"
)

/*
GenBuildDefinition is a helper function to construct
a SLSA v1 BuildDefinition struct.
Validation is handled in GenProvenance().
*/
func GenBuildDefinition(buildType string, externalParams *structpb.Struct, internalParams *structpb.Struct, resolvedDependencies []*ita1.ResourceDescriptor) *prov1.BuildDefinition {
	buildDef := &prov1.BuildDefinition{
		BuildType:            buildType,
		ExternalParameters:   externalParams,
		InternalParameters:   internalParams,
		ResolvedDependencies: resolvedDependencies,
	}

	return buildDef
}

/*
GenRunDetails is a helper function to construct
a SLSA v1 RunDetails struct.
Validation is handled in GenProvenance().
*/
func GenRunDetails(builder *prov1.Builder, metadata *prov1.BuildMetadata, byproducts []*ita1.ResourceDescriptor) *prov1.RunDetails {
	runDetails := &prov1.RunDetails{
		Builder:    builder,
		Metadata:   metadata,
		Byproducts: byproducts,
	}

	return runDetails
}

/*
GenBuilder is a helper function to construct a
SLSA v1 Builder struct.
Validation is handled in GenProvenance().
*/
func GenBuilder(id string, version map[string]string, builderDependencies []*ita1.ResourceDescriptor) *prov1.Builder {
	builder := &prov1.Builder{
		Id:                  id,
		Version:             version,
		BuilderDependencies: builderDependencies,
	}

	return builder
}

/*
GenBuildMetadata is a helper function to construct a
SLSA v1 BuildMetadata struct.
Because none of the fields of the object are required, this
constructor does not validate the contents of the struct
and always succeeds.
*/
func GenBuildMetadata(invocationID string, startedOn time.Time, finishedOn time.Time) *prov1.BuildMetadata {
	buildMetadata := &prov1.BuildMetadata{
		InvocationId: invocationID,
		StartedOn:    timestamppb.New(startedOn),
		FinishedOn:   timestamppb.New(finishedOn),
	}

	return buildMetadata
}

/*
GenerateValidPredicate constructs a SLSA v1 Provenance struct.
If the created object does not represent a valid Provenance, this
function returns an error.
*/
func GenerateValidPredicate(buildDefinition *prov1.BuildDefinition, runDetails *prov1.RunDetails) (*prov1.Provenance, error) {
	provenance := &prov1.Provenance{
		BuildDefinition: buildDefinition,
		RunDetails:      runDetails,
	}

	if err := provenance.Validate(); err != nil {
		return nil, fmt.Errorf("Invalid Provenance format: %w", err)
	}

	return provenance, nil
}
