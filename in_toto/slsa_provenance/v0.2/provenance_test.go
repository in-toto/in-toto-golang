package v02

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestDecodeProvenancePredicate(t *testing.T) {
	// Data from example in specification for generalized link format,
	// subject and materials trimmed.
	var data = `
{
    "builder": { "id": "https://github.com/Attestations/GitHubHostedActions@v1" },
	"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
    "invocation": {
      "configSource": {
		"uri": "git+https://github.com/curl/curl-docker@master",
        "digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" },   
		"entryPoint": "build.yaml:maketgz"
	  }
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
		Builder: ProvenanceBuilder{
			ID: "https://github.com/Attestations/GitHubHostedActions@v1",
		},
		BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		Invocation: ProvenanceInvocation{
			ConfigSource: ConfigSource{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: DigestSet{
					"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
				},
				EntryPoint: "build.yaml:maketgz",
			},
		},
		Metadata: &ProvenanceMetadata{
			BuildStartedOn: &testTime,
			Completeness: ProvenanceComplete{
				Environment: true,
			},
		},
		Materials: []ProvenanceMaterial{
			{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: DigestSet{
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
		t.Fatalf("failed to unmarshal json: %s\n", err)
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
		Builder: ProvenanceBuilder{
			ID: "https://github.com/Attestations/GitHubHostedActions@v1",
		},
		BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		Invocation: ProvenanceInvocation{
			ConfigSource: ConfigSource{
				EntryPoint: "build.yaml:maketgz",
				URI:        "git+https://github.com/curl/curl-docker@master",
				Digest: DigestSet{
					"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
				},
			},
		},
		BuildConfig: []string{"step1", "step2"},
		Metadata: &ProvenanceMetadata{
			BuildStartedOn:  &testTime,
			BuildFinishedOn: &testTime,
			Completeness: ProvenanceComplete{
				Parameters:  true,
				Environment: false,
				Materials:   true,
			},
		},
		Materials: []ProvenanceMaterial{
			{
				URI: "git+https://github.com/curl/curl-docker@master",
				Digest: DigestSet{
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
	var want = `{"builder":{"id":"https://github.com/Attestations/GitHubHostedActions@v1"},"buildType":"https://github.com/Attestations/GitHubActionsWorkflow@v1","invocation":{"configSource":{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"},"entryPoint":"build.yaml:maketgz"}},"buildConfig":["step1","step2"],"metadata":{"buildStartedOn":"2020-08-19T08:38:00Z","buildFinishedOn":"2020-08-19T08:38:00Z","completeness":{"parameters":true,"environment":false,"materials":true},"reproducible":false},"materials":[{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"}},{"uri":"github_hosted_vm:ubuntu-18.04:20210123.1"},{"uri":"git+https://github.com/curl/"}]}`
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
			Parameters: true,
		},
		Reproducible: true,
	}
	var want = `{"completeness":{"parameters":true,"environment":false,"materials":false},"reproducible":true}`
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

func TestInvocation(t *testing.T) {
	var r = ProvenanceInvocation{
		ConfigSource: ConfigSource{
			EntryPoint: "testEntry",
		},
	}
	var want = `{"configSource":{"entryPoint":"testEntry"}}`
	var got ProvenanceInvocation
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
}
