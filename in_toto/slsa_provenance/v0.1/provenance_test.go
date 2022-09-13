package v01

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/stretchr/testify/assert"
)

func TestDecodeProvenancePredicate(t *testing.T) {
	// Data from example in specification for generalized link format,
	// subject and materials trimmed.
	var data = `
{
    "builder": { "id": "https://github.com/Attestations/GitHubHostedActions@v1" },
    "recipe": {
      "type": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
      "definedInMaterial": 0,
      "entryPoint": "build.yaml:maketgz"
    },
    "metadata": {
      "buildStartedOn": "2020-08-19T08:38:00Z",
      "completeness": {
          "environment": true
      }
    },
    "materials": [
      {
        "uri": "git+https://github.com/curl/curl-docker@master",
        "digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
      }, {
        "uri": "github_hosted_vm:ubuntu-18.04:20210123.1"
      }
    ]
}
`
	var testTime = time.Unix(1597826280, 0)
	var want = ProvenancePredicate{
		Builder: common.ProvenanceBuilder{
			ID: "https://github.com/Attestations/GitHubHostedActions@v1",
		},
		Recipe: ProvenanceRecipe{
			Type:              "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			DefinedInMaterial: new(int),
			EntryPoint:        "build.yaml:maketgz",
		},
		Metadata: &ProvenanceMetadata{
			BuildStartedOn: &testTime,
			Completeness: ProvenanceComplete{
				Environment: true,
			},
		},
		Materials: []common.ProvenanceMaterial{
			{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: common.DigestSet{
					"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
				},
			},
			{
				URI: "github_hosted_vm:ubuntu-18.04:20210123.1",
			},
		},
	}
	var got ProvenancePredicate

	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Errorf("failed to unmarshal json: %s\n", err)
		return
	}

	// Make sure parsed time have same location set, location is only used
	// for display purposes.
	loc := want.Metadata.BuildStartedOn.Location()
	tmp := got.Metadata.BuildStartedOn.In(loc)
	got.Metadata.BuildStartedOn = &tmp

	assert.Equal(t, want, got, "Unexpected object after decoding")
}

func TestEncodeProvenancePredicate(t *testing.T) {
	var testTime = time.Unix(1597826280, 0).In(time.UTC)
	var p = ProvenancePredicate{
		Builder: common.ProvenanceBuilder{
			ID: "https://github.com/Attestations/GitHubHostedActions@v1",
		},
		Recipe: ProvenanceRecipe{
			Type:              "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			DefinedInMaterial: new(int),
			EntryPoint:        "build.yaml:maketgz",
		},
		Metadata: &ProvenanceMetadata{
			BuildStartedOn:  &testTime,
			BuildFinishedOn: &testTime,
			Completeness: ProvenanceComplete{
				Arguments:   true,
				Environment: false,
				Materials:   true,
			},
		},
		Materials: []common.ProvenanceMaterial{
			{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: common.DigestSet{
					"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
				},
			},
			{
				URI: "github_hosted_vm:ubuntu-18.04:20210123.1",
			},
			{
				URI: "git+https://github.com/curl/",
			},
		},
	}
	var want = `{"builder":{"id":"https://github.com/Attestations/GitHubHostedActions@v1"},"recipe":{"type":"https://github.com/Attestations/GitHubActionsWorkflow@v1","definedInMaterial":0,"entryPoint":"build.yaml:maketgz"},"metadata":{"buildStartedOn":"2020-08-19T08:38:00Z","buildFinishedOn":"2020-08-19T08:38:00Z","completeness":{"arguments":true,"environment":false,"materials":true},"reproducible":false},"materials":[{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"}},{"uri":"github_hosted_vm:ubuntu-18.04:20210123.1"},{"uri":"git+https://github.com/curl/"}]}`
	b, err := json.Marshal(&p)
	assert.Nil(t, err, "Error during JSON marshal")
	if d := cmp.Diff(want, string(b)); d != "" {
		t.Fatal(d)
	}
	assert.Equal(t, want, string(b), "Wrong JSON produced")
}

// Test that the default date (January 1, year 1, 00:00:00 UTC) is
// not marshalled
func TestMetadataNoTime(t *testing.T) {
	var md = ProvenanceMetadata{
		Completeness: ProvenanceComplete{
			Arguments: true,
		},
		Reproducible: true,
	}
	var want = `{"completeness":{"arguments":true,"environment":false,"materials":false},"reproducible":true}`
	var got ProvenanceMetadata
	b, err := json.Marshal(&md)

	t.Run("Marshal", func(t *testing.T) {
		assert.Nil(t, err, "Error during JSON marshal")
		assert.Equal(t, want, string(b), "Wrong JSON produced")
	})

	t.Run("Unmashal", func(t *testing.T) {
		err := json.Unmarshal(b, &got)
		assert.Nil(t, err, "Error during JSON unmarshal")
		assert.Equal(t, md, got, "Wrong struct after JSON unmarshal")
	})
}

// Verify that the behaviour of definedInMaterial can be controlled,
// as there is a semantic difference in value present or 0.
func TestRecipe(t *testing.T) {
	var r = ProvenanceRecipe{
		Type:       "testType",
		EntryPoint: "testEntry",
	}
	var want = `{"type":"testType","entryPoint":"testEntry"}`
	var got ProvenanceRecipe
	b, err := json.Marshal(&r)

	t.Run("No time/marshal", func(t *testing.T) {
		assert.Nil(t, err, "Error during JSON marshal")
		assert.Equal(t, want, string(b), "Wrong JSON produced")
	})

	t.Run("No time/unmarshal", func(t *testing.T) {
		err = json.Unmarshal(b, &got)
		assert.Nil(t, err, "Error during JSON unmarshal")
		assert.Equal(t, r, got, "Wrong struct after JSON unmarshal")
	})

	// Set time to zero and run test again
	r.DefinedInMaterial = new(int)
	want = `{"type":"testType","definedInMaterial":0,"entryPoint":"testEntry"}`
	b, err = json.Marshal(&r)

	t.Run("With time/marshal", func(t *testing.T) {
		assert.Nil(t, err, "Error during JSON marshal")
		assert.Equal(t, want, string(b), "Wrong JSON produced")
	})

	t.Run("With time/unmarshal", func(t *testing.T) {
		err = json.Unmarshal(b, &got)
		assert.Nil(t, err, "Error during JSON unmarshal")
		assert.Equal(t, r, got, "Wrong struct after JSON unmarshal")
	})
}
