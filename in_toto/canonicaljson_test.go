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
			"int":    3,
			"int2":   float64(42),
			"string": `\"`,
		},
	}
	expectedResult := []string{
		`{"keyid":"","keyid_hash_algorithms":null,"keytype":"","keyval":{"private":"","public":""},"scheme":""}`,
		`{"keyid":"id","keyid_hash_algorithms":["hash"],"keytype":"type","keyval":{"private":"priv","public":"pub"},"scheme":"scheme"}`,
		`{"false":false,"int":3,"int2":42,"nil":null,"string":"\\\"","true":true}`,
		"",
	}
	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])

		if string(result) != expectedResult[i] || err != nil {
			t.Errorf("EncodeCanonical returned (%s, %s), expected (%s, nil)",
				result, err, expectedResult[i])
		}
	}
}

func TestEncodeCanonicalErr(t *testing.T) {
	objects := []interface{}{
		map[string]interface{}{"float": 3.14159265359},
		TestEncodeCanonical,
	}
	errPart := []string{
		"Can't canonicalize floating point number",
		"unsupported type: func(",
	}

	for i := 0; i < len(objects); i++ {
		result, err := EncodeCanonical(objects[i])
		if err == nil || !strings.Contains(err.Error(), errPart[i]) {
			t.Errorf("EncodeCanonical returned (%s, %s), expected '%s' error",
				result, err, errPart[i])
		}
	}
}

func Test_encodeCanonical(t *testing.T) {
	expectedError := "Can't canonicalize"

	objects := []interface{}{
		Test_encodeCanonical,
		[]interface{}{Test_encodeCanonical},
	}

	for i := 0; i < len(objects); i++ {
		var result bytes.Buffer
		err := _encodeCanonical(objects[i], &result)
		if err == nil || !strings.Contains(err.Error(), expectedError) {
			t.Errorf("EncodeCanonical returned '%s', expected '%s' error",
				err, expectedError)
		}
	}
}
