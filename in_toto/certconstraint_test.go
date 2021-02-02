package in_toto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCheckConstraintAttribute(t *testing.T) {
	cases := []struct {
		Allowed  []string
		Test     []string
		Expected bool
	}{
		{
			Allowed:  []string{"test1", "test2"},
			Test:     []string{"test2", "test1"},
			Expected: true,
		}, {
			Allowed:  []string{"test1", "test2"},
			Test:     []string{"test2"},
			Expected: false,
		}, {
			Allowed:  []string{AllowAllConstraint},
			Test:     []string{"any", "thing", "goes"},
			Expected: true,
		}, {
			Allowed:  []string{},
			Test:     []string{},
			Expected: true,
		}, {
			Allowed:  []string{},
			Test:     []string{"test1"},
			Expected: false,
		}, {
			Allowed:  []string{"test1", "test2"},
			Test:     []string{"test1", "test2", "test3"},
			Expected: false,
		},
	}

	for _, c := range cases {
		actual := checkConstraintAttribute(c.Allowed, c.Test)
		if actual != c.Expected {
			t.Errorf("Got %v when expected %v. Allowed: %v, Test: %v", actual, c.Expected, c.Allowed, c.Test)
		}
	}
}

func TestConstraintCheck(t *testing.T) {
	// this cert has a CN of step1.example.com, and a URI of spiffe://example.com/step1
	testCertPem, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgIUExxFTHRndhbwwBlFSaItPQbhYSMwDQYJKoZIhvcNAQEL
BQAwMjEQMA4GA1UECgwHZXhhbXBsZTEeMBwGA1UECwwVZXhhbXBsZUNOPWV4YW1w
bGUuY29tMB4XDTIxMDEyODAxMjk0NVoXDTIxMDEyOTAxMjk0NVowQDEaMBgGA1UE
AwwRc3RlcDEuZXhhbXBsZS5jb20xEDAOBgNVBAsMB2V4YW1wbGUxEDAOBgNVBAoM
B2V4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDY6FZ2if5B
5LeQRAFMMM3S1tdAP7eKiLiMj7Zlsey4EGorNrRP6Pscqgmg6DLaGg24AafEfgP0
JQ7w4HtaHESk8SRr+C0lgvJxalMKoh0B99sXBulTnsPnjo4gLOVjEyPDbSoyjeyQ
8tkjtkFtMIb3gzE8WbPzWOrux6ME3Yat96Dp+y0n8fXhm+EIcnQqy/tyHQSVnDJy
5nYXDAcDYGwjM1klYaUZDSJUbhDy3aRTFdNnMhVdTcQWGZfh/rHmNzi2X+BSBnBH
tc4nGd1gw23iPtGQxcLzGQngtBVmMPs/lACkrHWkYZ4AQg5wKBtPvSKazOhd7vsy
cwHBSDMHcqZbAgMBAAGjRzBFMCgGA1UdEQEB/wQeMByGGnNwaWZmZTovL2V4YW1w
bGUuY29tL3N0ZXAxMA4GA1UdDwEB/wQEAwIF4DAJBgNVHRMEAjAAMA0GCSqGSIb3
DQEBCwUAA4IBAQCJOoVzTavmbhC6VmwwOvwTZffpTO1AJImB0E1Yia62AQ4Z9G4c
X1tmiSqIYuKzmZzXl3cvwFsA3Za2Kv3DPjasgd1ge7tkeiBtAh+yZbRyCHtFw9kJ
zMMz+wN5pnWb9e69gVkxyXc9FhzM4DNMLeupcRivxpo650N+LzRnEY/UKHyQgnyK
Bh47mx/lMz81znHjW2MucWtym6qJAdYOw1VL+5gq1jfrl8azIvgOiaPGf7rRGYCA
QYXYItG+6fK1B/xS14Hx7pqoG7MtOR3bsljygfsNIlw5NKjX+EIQDl1CzLtNw1NH
yORP9/XlC7SjBgRsX0Jy2p1OXRiu4tvCottJ
-----END CERTIFICATE-----`))

	testCert, err := x509.ParseCertificate(testCertPem.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate from pem bytes: %v", err)
	}

	cases := []struct {
		Constraint CertificateConstraint
		Cert       *x509.Certificate
		Expected   bool
	}{{
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "step1.example.com",
			URIs:       []string{"spiffe://example.com/step1"},
		},
		Expected: true,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "*",
			URIs:       []string{"spiffe://example.com/step1"},
		},
		Expected: true,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "step1.example.com",
			URIs:       []string{"*"},
		},
		Expected: true,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "",
			URIs:       []string{"*"},
		},
		Expected: false,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "step1.example.com",
			URIs:       []string{""},
		},
		Expected: false,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "step1.example.com",
			URIs:       []string{"spiffe://example.com/step1", "step1.example.com"},
		},
		Expected: false,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "step1.example.com",
			URIs:       []string{},
		},
		Expected: false,
	}, {
		Cert: testCert,
		Constraint: CertificateConstraint{
			CommonName: "",
			URIs:       []string{},
		},
		Expected: false,
	},
	}

	for _, c := range cases {
		actual := c.Constraint.Check(c.Cert)
		if actual != c.Expected {
			t.Errorf("Got %v when expected %v. Constraint: %v, Certificate: %v", actual, c.Expected, c.Constraint, c.Cert)
		}
	}
}
