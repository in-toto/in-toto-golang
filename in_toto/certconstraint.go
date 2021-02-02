package in_toto

import (
	"crypto/x509"
	"net/url"
)

const (
	AllowAllConstraint = "*"
)

// CertificateConstraint defines the attributes a certificate must have to act as a functionary.
// A wildcard `*` allows any value in the specified attribute, where as an empty array or value
// asserts that the certificate must have nothing for that attribute. A certificate must have
// every value defined in a constraint to match.
type CertificateConstraint struct {
	CommonName string   `json:"common_name"`
	URIs       []string `json:"uris"`
}

// Check tests the provided certificate against the constraint. True is returned if the certificate
// satisifies the constraint, false will be returned otherwise.
func (cc CertificateConstraint) Check(cert *x509.Certificate) bool {
	if cc.CommonName != AllowAllConstraint && cc.CommonName != cert.Subject.CommonName {
		return false
	}

	return checkConstraintAttribute(cc.URIs, urisToStrings(cert.URIs))
}

// urisToStrings is a helper that converts a list of URL objects to the string that represents them
func urisToStrings(uris []*url.URL) []string {
	res := make([]string, 0, len(uris))
	for _, uri := range uris {
		res = append(res, uri.String())
	}

	return res
}

// checkConstraintAttribute tests that the provided test values match the allowed values of the constraint.
// All allowed values must be met one-to-one to be considered a successful match.
func checkConstraintAttribute(allowed, test []string) bool {
	if len(allowed) == 1 && allowed[0] == AllowAllConstraint {
		return true
	}

	unmet := NewSet(allowed...)
	for _, t := range test {
		// if our test has a value we didn't expect, fail early
		if !unmet.Has(t) {
			return false
		}

		// consider the constraint met
		unmet.Remove(t)
	}

	// if we have any unmet left after going through each test value, fail.
	return len(unmet) == 0
}
