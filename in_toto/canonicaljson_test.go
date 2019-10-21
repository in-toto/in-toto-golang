package in_toto

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeCanonical(t *testing.T) {
	objects := []interface{}{
		Key{},
		Key{
			KeyVal: KeyVal{
				Private: "priv",
				Public:  "pub",
			},
			KeyIdHashAlgorithms: []string{"hash"},
			KeyId:               "id",
			KeyType:             "type",
			Scheme:              "scheme",
		},
		map[string]interface{}{
			"true":   true,
			"false":  false,
			"nil":    nil,
			"float":  3.14159265359,
			"string": `\"`,
		},
	}
	expectedResult := []string{
		`{"keyid":"","keyid_hash_algorithms":null,"keytype":"","keyval":{"private":"","public":""},"scheme":""}`,
		`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"private":"priv","public":"pub"},"scheme":"scheme"}`,
		`{"false":false,"float":3,"nil":null,"string":"\\\"","true":true}`,
		"",
	}
	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])

		if string(result) != expectedResult[i] || err != nil {
			t.Errorf("EncodeCanonical returned (%s, %s), expected (%s, nil)",
				result, err, expectedResult[i])
		}
	}

	// Cannot canonicalize function
	result, err := EncodeCanonical(TestEncodeCanonical)
	expectedError := "json: unsupported type"
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Errorf("EncodeCanonical returned (%s, %s), expected '%s' error",
			result, err, expectedError)
	}
}

func Test_encodeCanonical(t *testing.T) {
	var result bytes.Buffer
	err := _encodeCanonical(Test_encodeCanonical, &result)
	expectedError := "Can't canonicalize"
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Errorf("EncodeCanonical returned '%s', expected '%s' error",
			err, expectedError)
	}
}
