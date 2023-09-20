package in_toto

import (
	"fmt"

	ita1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// StatementInTotoV01 is the statement type for the generalized link format
	// containing statements. This is constant for all predicate types.
	StatementInTotoV01 = "https://in-toto.io/Statement/v0.1"

	// StatementInTotoV1 is the type URI for ITE-6 v1 Statements.
	// This is constant for all predicate types.
	StatementInTotoV1 = ita1.StatementTypeUri

	// PredicateSPDX represents a SBOM using the SPDX standard.
	// The SPDX mandates 'spdxVersion' field, so predicate type can omit
	// version.
	PredicateSPDX = "https://spdx.dev/Document"
	// PredicateCycloneDX represents a CycloneDX SBOM
	PredicateCycloneDX = "https://cyclonedx.org/bom"
	// PredicateLinkV1 represents an in-toto 0.9 link.
	PredicateLinkV1 = "https://in-toto.io/Link/v1"
)

// Subject describes the set of software artifacts the statement applies to.
//
// Deprecated: This implementation of Subject exists for historical
// compatibility and should not be used. This implementation has been
// superseded by a ResourceDescriptor struct generated from the Protobuf
// definition in
// https://github.com/in-toto/attestation/tree/main/protos/in_toto_attestation/v1.
// To generate an ITE-6 v1 Statement subject, use the ResourceDescriptor Go
// APIs provided in https://github.com/in-toto/attestation/tree/main/go/v1.
type Subject struct {
	Name   string           `json:"name"`
	Digest common.DigestSet `json:"digest"`
}

// StatementHeader defines the common fields for all statements
//
// Deprecated: This implementation of StatementHeader exists for historical
// compatibility and should not be used. This implementation has been
// superseded by the Statement struct generated from the Protobuf
// definition in
// https://github.com/in-toto/attestation/tree/main/protos/in_toto_attestation/v1.
// To generate an ITE-6 v1 Statement, use the Go APIs provided in
// https://github.com/in-toto/attestation/tree/main/go/v1.
type StatementHeader struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []Subject `json:"subject"`
}

/*
Statement binds the attestation to a particular subject and identifies the
of the predicate. This struct represents a generic statement.
*/
// Deprecated: This implementation of Statement exists for historical
// compatibility and should not be used. This implementation has been
// superseded by the Statement struct generated from the Protobuf
// definition in
// https://github.com/in-toto/attestation/tree/main/protos/in_toto_attestation/v1.
// To generate an ITE-6 v1 Statement, use the Go APIs provided in
// https://github.com/in-toto/attestation/tree/main/go/v1.
type Statement struct {
	StatementHeader
	// Predicate contains type speficic metadata.
	Predicate interface{} `json:"predicate"`
}

// ProvenanceStatementSLSA01 is the definition for an entire provenance statement with SLSA 0.1 predicate.
type ProvenanceStatementSLSA01 struct {
	StatementHeader
	Predicate slsa01.ProvenancePredicate `json:"predicate"`
}

// ProvenanceStatementSLSA02 is the definition for an entire provenance statement with SLSA 0.2 predicate.
type ProvenanceStatementSLSA02 struct {
	StatementHeader
	Predicate slsa02.ProvenancePredicate `json:"predicate"`
}

// ProvenanceStatementSLSA1 is the definition for an entire provenance statement with SLSA 1.0 predicate.
//
// Deprecated: ProvenanceStatementSLSA1 exists for historical
// compatibility and should not be used. To generate an ITE-6 v1 Statement
// with an ITE-9 Provenance v1 predicate, use the Go APIs provided in
// https://github.com/in-toto/attestation/tree/main/go.
type ProvenanceStatementSLSA1 struct {
	StatementHeader
	Predicate slsa1.ProvenancePredicate `json:"predicate"`
}

// ProvenanceStatement is the definition for an entire provenance statement with SLSA 0.2 predicate.
// Deprecated: Only version-specific provenance structs will be maintained (ProvenanceStatementSLSA01, ProvenanceStatementSLSA02).
type ProvenanceStatement struct {
	StatementHeader
	Predicate slsa02.ProvenancePredicate `json:"predicate"`
}

// LinkStatement is the definition for an entire link statement.
type LinkStatement struct {
	StatementHeader
	Predicate Link `json:"predicate"`
}

/*
SPDXStatement is the definition for an entire SPDX statement.
This is currently not implemented. Some tooling exists here:
https://github.com/spdx/tools-golang, but this software is still in
early state.
This struct is the same as the generic Statement struct but is added for
completeness
*/
type SPDXStatement struct {
	StatementHeader
	Predicate interface{} `json:"predicate"`
}

/*
CycloneDXStatement defines a cyclonedx sbom in the predicate. It is not
currently serialized just as its SPDX counterpart. It is an empty
interface, like the generic Statement.
*/
type CycloneDXStatement struct {
	StatementHeader
	Predicate interface{} `json:"predicate"`
}

func GenResourceDescriptor(name string, uri string, digestSet map[string]string, content []byte, downloadLocation string, mediaType string, annotations *structpb.Struct) (*ita1.ResourceDescriptor, error) {
	rd := &ita1.ResourceDescriptor{
		Name:             name,
		Uri:              uri,
		Digest:           digestSet,
		Content:          content,
		DownloadLocation: downloadLocation,
		MediaType:        mediaType,
		Annotations:      annotations,
	}

	err := rd.Validate()
	if err != nil {
		return nil, fmt.Errorf("Invalid resource descriptor: %w", err)
	}

	return rd, nil
}

func GenStatementV1(subject []*ita1.ResourceDescriptor, predicateType string, predicate *structpb.Struct) (*ita1.Statement, error) {
	st := &ita1.Statement{
		Type:          StatementInTotoV1,
		Subject:       subject,
		PredicateType: predicateType,
		Predicate:     predicate,
	}

	err := st.Validate()
	if err != nil {
		return nil, fmt.Errorf("Invalid in-toto Statement: %w", err)
	}

	return st, nil
}

func PredicatePbToStruct(predicatePb proto.Message) (*structpb.Struct, error) {
	predJson, err := protojson.Marshal(predicatePb)
	if err != nil {
		return nil, err
	}

	predStruct := &structpb.Struct{}
	err = protojson.Unmarshal(predJson, predStruct)
	if err != nil {
		return nil, err
	}

	return predStruct, nil
}

/*
RDListFromRecord converts a map of artifacts as collected
by RecordArtifacts() in runlib.go and converts it into a list
of ITE-6 ResourceDescriptors to be used in v1 Statements.
*/
func RDListFromRecord(evalArtifacts map[string]interface{}) ([]*ita1.ResourceDescriptor, error) {
	var rds []*ita1.ResourceDescriptor
	for name, digestSet := range evalArtifacts {

		rd, err := GenResourceDescriptor(name, "", digestSet, nil, "", "", nil)

		if err != nil {
			return nil, err
		}

		rds = append(rds, rd)
	}

	return rds, nil
}
