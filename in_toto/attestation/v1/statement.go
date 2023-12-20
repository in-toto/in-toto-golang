package v1

import (
	"fmt"

	ita1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

/*
GenerateValidStatement constructs an in-toto Attestation Framework v1
Statement struct. If the created object does not represent a
compliant Statement, this function returns an error.
*/
func GenerateValidStatement(subject []*ita1.ResourceDescriptor, predicateType string, predicate *structpb.Struct) (*ita1.Statement, error) {
	st := &ita1.Statement{
		Type:          ita1.StatementTypeUri,
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
