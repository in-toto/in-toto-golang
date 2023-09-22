package v1

import (
	"fmt"

	ita1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// StatementInTotoV1 is the type URI for ITE-6 v1 Statements.
// This is constant for all predicate types.
const StatementInTotoV1 = ita1.StatementTypeUri

/*
GenStatement constructs an in-toto Attestation Framework v1
Statement struct. If the created object does not represent a
compliant Statement, this function returns an error.
*/
func GenStatement(subject []*ita1.ResourceDescriptor, predicateType string, predicate *structpb.Struct) (*ita1.Statement, error) {
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
