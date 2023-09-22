package common

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

/*
PredicatePbToStruct converts a given protobuf representation of
an in-toto attestation Predicate into a generic Struct struct
needed to construct an in-toto Attestation Framework v1
compliant Statement. If there are any marshalling problems,
this function returns an error.
*/
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
