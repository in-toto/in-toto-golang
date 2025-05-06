package in_toto

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	slsa02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/stretchr/testify/assert"
)

func TestDecodeProvenanceStatementSLSA02(t *testing.T) {
	// Data from example in specification for generalized link format,
	// subject and materials trimmed.
	var data = `
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "curl-7.72.0.tar.bz2",
      "digest": { "sha256": "ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef" }},
    { "name": "curl-7.72.0.tar.gz",
      "digest": { "sha256": "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2" }}
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
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
}
`

	var testTime = time.Unix(1597826280, 0)
	var want = ProvenanceStatement{
		StatementHeader: StatementHeader{
			Type:          StatementInTotoV01,
			PredicateType: slsa02.PredicateSLSAProvenance,
			Subject: []Subject{
				{
					Name: "curl-7.72.0.tar.bz2",
					Digest: common.DigestSet{
						"sha256": "ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef",
					},
				},
				{
					Name: "curl-7.72.0.tar.gz",
					Digest: common.DigestSet{
						"sha256": "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2",
					},
				},
			},
		},
		Predicate: slsa02.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: "https://github.com/Attestations/GitHubHostedActions@v1",
			},
			BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			Invocation: slsa02.ProvenanceInvocation{
				ConfigSource: slsa02.ConfigSource{
					EntryPoint: "build.yaml:maketgz",
					URI:        "git+https://github.com/curl/curl-docker@master",
					Digest: common.DigestSet{
						"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
					},
				},
			},
			Metadata: &slsa02.ProvenanceMetadata{
				BuildStartedOn: &testTime,
				Completeness: slsa02.ProvenanceComplete{
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
		},
	}
	var got ProvenanceStatement

	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Errorf("failed to unmarshal json: %s\n", err)
		return
	}

	// Make sure parsed time have same location set, location is only used
	// for display purposes.
	loc := want.Predicate.Metadata.BuildStartedOn.Location()
	tmp := got.Predicate.Metadata.BuildStartedOn.In(loc)
	got.Predicate.Metadata.BuildStartedOn = &tmp

	assert.Equal(t, want, got, "Unexpected object after decoding")
}

func TestEncodeProvenanceStatementSLSA02(t *testing.T) {
	var testTime = time.Unix(1597826280, 0)
	var p = ProvenanceStatement{
		StatementHeader: StatementHeader{
			Type:          StatementInTotoV01,
			PredicateType: slsa02.PredicateSLSAProvenance,
			Subject: []Subject{
				{
					Name: "curl-7.72.0.tar.bz2",
					Digest: common.DigestSet{
						"sha256": "ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef",
					},
				},
				{
					Name: "curl-7.72.0.tar.gz",
					Digest: common.DigestSet{
						"sha256": "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2",
					},
				},
			},
		},
		Predicate: slsa02.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: "https://github.com/Attestations/GitHubHostedActions@v1",
			},
			BuildType: "https://github.com/Attestations/GitHubActionsWorkflow@v1",
			Invocation: slsa02.ProvenanceInvocation{
				ConfigSource: slsa02.ConfigSource{
					URI: "git+https://github.com/curl/curl-docker@master",
					Digest: common.DigestSet{
						"sha1": "d6525c840a62b398424a78d792f457477135d0cf",
					},
					EntryPoint: "build.yaml:maketgz",
				},
			},
			Metadata: &slsa02.ProvenanceMetadata{
				BuildStartedOn:  &testTime,
				BuildFinishedOn: &testTime,
				Completeness: slsa02.ProvenanceComplete{
					Parameters:  true,
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
		},
	}
	var want = `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.2","subject":[{"name":"curl-7.72.0.tar.bz2","digest":{"sha256":"ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef"}},{"name":"curl-7.72.0.tar.gz","digest":{"sha256":"d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2"}}],"predicate":{"builder":{"id":"https://github.com/Attestations/GitHubHostedActions@v1"},"buildType":"https://github.com/Attestations/GitHubActionsWorkflow@v1","invocation":{"configSource":{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"},"entryPoint":"build.yaml:maketgz"}},"metadata":{"buildStartedOn":"2020-08-19T08:38:00Z","buildFinishedOn":"2020-08-19T08:38:00Z","completeness":{"parameters":true,"environment":false,"materials":true},"reproducible":false},"materials":[{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"}},{"uri":"github_hosted_vm:ubuntu-18.04:20210123.1"},{"uri":"git+https://github.com/curl/"}]}}`

	b, err := json.Marshal(&p)
	assert.Nil(t, err, "Error during JSON marshal")
	assert.Equal(t, want, string(b), "Wrong JSON produced")
}

func TestDecodeProvenanceStatementSLSA01(t *testing.T) {
	// Data from example in specification for generalized link format,
	// subject and materials trimmed.
	var data = `
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "curl-7.72.0.tar.bz2",
      "digest": { "sha256": "ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef" }},
    { "name": "curl-7.72.0.tar.gz",
      "digest": { "sha256": "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2" }}
  ],
  "predicateType": "https://slsa.dev/provenance/v0.1",
  "predicate": {
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
}
`

	var testTime = time.Unix(1597826280, 0)
	var want = ProvenanceStatementSLSA01{
		StatementHeader: StatementHeader{
			Type:          StatementInTotoV01,
			PredicateType: slsa01.PredicateSLSAProvenance,
			Subject: []Subject{
				{
					Name: "curl-7.72.0.tar.bz2",
					Digest: common.DigestSet{
						"sha256": "ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef",
					},
				},
				{
					Name: "curl-7.72.0.tar.gz",
					Digest: common.DigestSet{
						"sha256": "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2",
					},
				},
			},
		},
		Predicate: slsa01.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: "https://github.com/Attestations/GitHubHostedActions@v1",
			},
			Recipe: slsa01.ProvenanceRecipe{
				Type:              "https://github.com/Attestations/GitHubActionsWorkflow@v1",
				DefinedInMaterial: new(int),
				EntryPoint:        "build.yaml:maketgz",
			},
			Metadata: &slsa01.ProvenanceMetadata{
				BuildStartedOn: &testTime,
				Completeness: slsa01.ProvenanceComplete{
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
		},
	}
	var got ProvenanceStatementSLSA01

	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Errorf("failed to unmarshal json: %s\n", err)
		return
	}

	// Make sure parsed time have same location set, location is only used
	// for display purposes.
	loc := want.Predicate.Metadata.BuildStartedOn.Location()
	tmp := got.Predicate.Metadata.BuildStartedOn.In(loc)
	got.Predicate.Metadata.BuildStartedOn = &tmp

	assert.Equal(t, want, got, "Unexpected object after decoding")
}

func TestEncodeProvenanceStatementSLSA01(t *testing.T) {
	var testTime = time.Unix(1597826280, 0)
	var p = ProvenanceStatementSLSA01{
		StatementHeader: StatementHeader{
			Type:          StatementInTotoV01,
			PredicateType: slsa01.PredicateSLSAProvenance,
			Subject: []Subject{
				{
					Name: "curl-7.72.0.tar.bz2",
					Digest: common.DigestSet{
						"sha256": "ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef",
					},
				},
				{
					Name: "curl-7.72.0.tar.gz",
					Digest: common.DigestSet{
						"sha256": "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2",
					},
				},
			},
		},
		Predicate: slsa01.ProvenancePredicate{
			Builder: common.ProvenanceBuilder{
				ID: "https://github.com/Attestations/GitHubHostedActions@v1",
			},
			Recipe: slsa01.ProvenanceRecipe{
				Type:              "https://github.com/Attestations/GitHubActionsWorkflow@v1",
				DefinedInMaterial: new(int),
				EntryPoint:        "build.yaml:maketgz",
			},
			Metadata: &slsa01.ProvenanceMetadata{
				BuildStartedOn:  &testTime,
				BuildFinishedOn: &testTime,
				Completeness: slsa01.ProvenanceComplete{
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
		},
	}
	var want = `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://slsa.dev/provenance/v0.1","subject":[{"name":"curl-7.72.0.tar.bz2","digest":{"sha256":"ad91970864102a59765e20ce16216efc9d6ad381471f7accceceab7d905703ef"}},{"name":"curl-7.72.0.tar.gz","digest":{"sha256":"d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2"}}],"predicate":{"builder":{"id":"https://github.com/Attestations/GitHubHostedActions@v1"},"recipe":{"type":"https://github.com/Attestations/GitHubActionsWorkflow@v1","definedInMaterial":0,"entryPoint":"build.yaml:maketgz"},"metadata":{"buildStartedOn":"2020-08-19T08:38:00Z","buildFinishedOn":"2020-08-19T08:38:00Z","completeness":{"arguments":true,"environment":false,"materials":true},"reproducible":false},"materials":[{"uri":"git+https://github.com/curl/curl-docker@master","digest":{"sha1":"d6525c840a62b398424a78d792f457477135d0cf"}},{"uri":"github_hosted_vm:ubuntu-18.04:20210123.1"},{"uri":"git+https://github.com/curl/"}]}}`

	b, err := json.Marshal(&p)
	assert.Nil(t, err, "Error during JSON marshal")
	assert.Equal(t, want, string(b), "Wrong JSON produced")
}

// Test that the default date (January 1, year 1, 00:00:00 UTC) is
// not marshalled
func TestMetadataNoTime(t *testing.T) {
	var md = slsa02.ProvenanceMetadata{
		Completeness: slsa02.ProvenanceComplete{
			Parameters: true,
		},
		Reproducible: true,
	}
	var want = `{"completeness":{"parameters":true,"environment":false,"materials":false},"reproducible":true}`
	var got slsa02.ProvenanceMetadata
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
	var r = slsa01.ProvenanceRecipe{
		Type:       "testType",
		EntryPoint: "testEntry",
	}
	var want = `{"type":"testType","entryPoint":"testEntry"}`
	var got slsa01.ProvenanceRecipe
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

func TestLinkStatement(t *testing.T) {
	var data = `
{
  "subject": [
     {"name": "baz",
      "digest": { "sha256": "hash1" }}
  ],
  "predicateType": "https://in-toto.io/Link/v1",
  "predicate": {
    "_type": "link",
    "name": "name",
    "command": ["cc", "-o", "baz", "baz.z"],
    "materials": {
       "kv": {"alg": "vv"}
    },
    "products": {
       "kp": {"alg": "vp"}
    },
    "byproducts": {
       "kb": "vb"
    },
    "environment": {
       "FOO": "BAR"
    }
  }
}
`

	var want = LinkStatement{
		StatementHeader: StatementHeader{
			PredicateType: PredicateLinkV1,
			Subject: []Subject{
				{
					Name: "baz",
					Digest: common.DigestSet{
						"sha256": "hash1",
					},
				},
			},
		},
		Predicate: Link{
			Type: "link",
			Name: "name",
			Materials: map[string]HashObj{
				"kv": {"alg": "vv"},
			},
			Products: map[string]HashObj{
				"kp": {"alg": "vp"},
			},
			ByProducts: map[string]interface{}{
				"kb": "vb",
			},
			Environment: map[string]interface{}{
				"FOO": "BAR",
			},
			Command: []string{"cc", "-o", "baz", "baz.z"},
		},
	}
	var got LinkStatement

	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Errorf("failed to unmarshal json: %s\n", err)
		return
	}

	assert.Equal(t, want, got, "Unexpected object after decoding")
}
