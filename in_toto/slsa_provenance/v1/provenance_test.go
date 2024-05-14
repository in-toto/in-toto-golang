package v1

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/stretchr/testify/assert"
)

func TestDecodeProvenancePredicate(t *testing.T) {
	var data = `
{
	"buildDefinition": {
		"buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
		"resolvedDependencies": [
			{
				"uri": "git+https://github.com/curl/curl-docker@master",
				"digest": { "sha1": "d6525c840a62b398424a78d792f457477135d0cf" }
			}, 
			{
				"uri": "github_hosted_vm:ubuntu-18.04:20210123.1"
			}
		]
	},
	"runDetails": {
		"builder": { 
			"id": "https://github.com/Attestations/GitHubHostedActions@v1" 
		},
		"metadata": {
			"startedOn": "2020-08-19T08:38:00Z"
		}
	}
}
`
	var testTime = time.Unix(1597826280, 0)
	var want = ProvenancePredicate{
		BuildDefinition: ProvenanceBuildDefinition{
			BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			ResolvedDependencies: []ResourceDescriptor{
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
		},
		RunDetails: ProvenanceRunDetails{
			Builder: Builder{
				ID: "https://github.com/Attestations/GitHubHostedActions@v1",
			},
			BuildMetadata: BuildMetadata{
				StartedOn: &testTime,
			},
		},
	}
	var got ProvenancePredicate

	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("failed to unmarshal json: %s\n", err)
	}

	// Make sure parsed time have same location set, location is only used
	// for display purposes.
	loc := want.RunDetails.BuildMetadata.StartedOn.Location()
	tmp := got.RunDetails.BuildMetadata.StartedOn.In(loc)
	got.RunDetails.BuildMetadata.StartedOn = &tmp

	assert.Equal(t, want, got, "Unexpected object after decoding")
}

func TestEncodeProvenancePredicate(t *testing.T) {
	var testTime = time.Unix(1597826280, 0).In(time.UTC)
	var p = ProvenancePredicate{
		BuildDefinition: ProvenanceBuildDefinition{
			BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			ExternalParameters: map[string]string{
				"entryPoint": "build.yaml:maketgz",
				"source":     "git+https://github.com/curl/curl-docker@master",
			},
			InternalParameters: map[string]string{
				"GITHUB_RUNNER": "github_hosted_vm:ubuntu-18.04:20210123.1",
			},
			ResolvedDependencies: []ResourceDescriptor{
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
		},
		RunDetails: ProvenanceRunDetails{
			Builder: Builder{
				ID: "https://github.com/Attestations/GitHubHostedActions@v1",
			},
			BuildMetadata: BuildMetadata{
				StartedOn:  &testTime,
				FinishedOn: &testTime,
			},
		},
	}
	var want = `{"buildDefinition":{"buildType":"https://github.com/Attestations/GitHubActionsWorkflow@v1","externalParameters":{"entryPoint":"build.yaml:maketgz","source":"git+https://github.com/curl/curl-docker@master"},"internalParameters":{"GITHUB_RUNNER":"github_hosted_vm:ubuntu-18.04:20210123.1"},"resolvedDependencies":[{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"}},{"uri":"github_hosted_vm:ubuntu-18.04:20210123.1"},{"uri":"git+https://github.com/curl/"}]},"runDetails":{"builder":{"id":"https://github.com/Attestations/GitHubHostedActions@v1"},"metadata":{"startedOn":"2020-08-19T08:38:00Z","finishedOn":"2020-08-19T08:38:00Z"}}}`
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
	var md = BuildMetadata{
		InvocationID: "123456-12-1",
	}
	var want = `{"invocationId":"123456-12-1"}`
	var got BuildMetadata
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
