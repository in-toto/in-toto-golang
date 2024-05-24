package in_toto

import (
	link "github.com/in-toto/attestation/go/predicates/link/v0"
	ita1 "github.com/in-toto/attestation/go/v1"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"google.golang.org/protobuf/encoding/protojson"
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

	/*
		Deprecated - use PredicateLink instead
		PredicateLinkV1 represents an in-toto 0.9 link.
	*/
	PredicateLinkV1 = "https://in-toto.io/Link/v1"

	// Represents an in-toto link predicate
	PredicateLink = "https://in-toto.io/attestation/link/v0.3"
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

/*
An Attestor is used to create in-toto Attestation
framework compliant metadata.

  - GenerateStatement exists to enable usage of alternative
    signing solutions.
  - Attest supports using the DSSE for signing
*/
type Attestor interface {
	GenerateStatement() (*v1.Statement, error)
	Attest() (*Envelope, error)
}

/*
LinkAttestor follows the in-toto Attestation framework
for a Link Predicate.
*/
type LinkAttestor struct {
	MaterialPaths     []string
	ProductPaths      []string
	HashAlgorithms    []string
	GitignorePatterns []string
	LStripPaths       []string
	CmdArgs           []string
	RunDir            string
	StepName          string
	LineNormalization bool
	FollowSymlinkDirs bool
	Key               Key
}

func (a *LinkAttestor) Attest() (*Envelope, error) {
	statement, err := a.GenerateStatement()
	if err != nil {
		return nil, err
	}

	return signStatement(statement, a.Key)
}

func (a *LinkAttestor) GenerateStatement() (*v1.Statement, error) {
	materials, err := RecordArtifacts(a.MaterialPaths, a.HashAlgorithms, a.GitignorePatterns, a.LStripPaths, a.LineNormalization, a.FollowSymlinkDirs)
	if err != nil {
		return nil, err
	}

	// make sure that we only run RunCommand if cmdArgs is not nil or empty
	byProducts := map[string]interface{}{}
	if len(a.CmdArgs) != 0 {
		byProducts, err = RunCommand(a.CmdArgs, a.RunDir)
		if err != nil {
			return nil, err
		}
	}

	products, err := RecordArtifacts(a.ProductPaths, a.HashAlgorithms, a.GitignorePatterns, a.LStripPaths, a.LineNormalization, a.FollowSymlinkDirs)
	if err != nil {
		return nil, err
	}

	var materialResources = make([]*v1.ResourceDescriptor, len(materials))
	matCount := 0
	for key, value := range materials {
		materialResources[matCount] = &v1.ResourceDescriptor{
			Name:   key,
			Digest: value,
		}

		matCount++
	}

	var productResources = make([]*v1.ResourceDescriptor, len(products))
	prdCount := 0
	for key, value := range products {
		productResources[0] = &v1.ResourceDescriptor{
			Name:   key,
			Digest: value,
		}

		prdCount++
	}

	byProductsStruct, err := structpb.NewStruct(byProducts)
	if err != nil {
		return nil, err
	}

	link := link.Link{
		Name:       a.StepName,
		Command:    a.CmdArgs,
		Materials:  materialResources,
		Byproducts: byProductsStruct,
	}

	linkJson, err := protojson.Marshal(&link)
	if err != nil {
		return nil, err
	}

	linkStruct := &structpb.Struct{}
	err = protojson.Unmarshal(linkJson, linkStruct)
	if err != nil {
		return nil, err
	}

	statement := v1.Statement{
		Type:          StatementInTotoV1,
		Subject:       productResources,
		PredicateType: PredicateLink,
		Predicate:     linkStruct,
	}

	err = statement.Validate()
	if err != nil {
		return nil, err
	}

	return &statement, nil
}

func signStatement(statement *v1.Statement, key Key) (*Envelope, error) {
	env := &Envelope{}
	if err := env.SetPayloadProtobuf(statement); err != nil {
		return nil, err
	}

	err := env.Sign(key)
	if err != nil {
		return nil, err
	}

	return env, nil
}
