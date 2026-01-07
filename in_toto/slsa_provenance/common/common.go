// Deprecated: This package has been deprecated in favor of https://github.com/in-toto/go-witness
package common

// DigestSet contains a set of digests. It is represented as a map from
// algorithm name to lowercase hex-encoded value.
type DigestSet map[string]string

// ProvenanceBuilder identifies the entity that executed the build steps.
type ProvenanceBuilder struct {
	ID string `json:"id"`
}

// ProvenanceMaterial defines the materials used to build an artifact.
type ProvenanceMaterial struct {
	URI    string    `json:"uri,omitempty"`
	Digest DigestSet `json:"digest,omitempty"`
}
