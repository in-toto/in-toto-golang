package v1

import (
	"fmt"

	ita1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

/*
GenerateValidResourceDescriptor constructs an in-toto Attestation Framework v1
ResourceDescriptor struct. If the created object does not represent a
valid ResourceDescriptor, this function returns an error.
*/
func GenerateValidResourceDescriptor(name string, uri string, digestSet map[string]string, content []byte, downloadLocation string, mediaType string, annotations *structpb.Struct) (*ita1.ResourceDescriptor, error) {
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

/*
RDListFromRecord converts a map of artifacts as collected
by RecordArtifacts() in runlib.go and converts it into a list
of ITE-6 ResourceDescriptors to be used in v1 Statements.
*/
func RDListFromRecord(evalArtifacts map[string]map[string]string) ([]*ita1.ResourceDescriptor, error) {
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
