package in_toto

import (
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/assert"
)

func TestEnvelopeSetPayload(t *testing.T) {
	t.Run("set layout payload", func(t *testing.T) {
		env := &Envelope{}

		payload := Layout{
			Type:    "layout",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
			Expires: "2030-01-01T12:00:00Z",
			Readme:  "readme",
		}

		err := env.SetPayload(payload)
		assert.Nil(t, err)
	})

	t.Run("set link payload", func(t *testing.T) {
		env := &Envelope{}

		payload := Link{
			Type:        "link",
			Name:        "test",
			Materials:   map[string]HashObj{},
			Products:    map[string]HashObj{},
			ByProducts:  map[string]any{},
			Environment: map[string]any{},
			Command:     []string{},
		}
		err := env.SetPayload(payload)
		assert.Nil(t, err)
	})
}

func TestEnvelopeGetPayload(t *testing.T) {
	t.Run("get layout payload", func(t *testing.T) {
		env := &Envelope{}

		payload := Layout{
			Type:    "layout",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
			Expires: "2030-01-01T12:00:00Z",
			Readme:  "readme",
		}

		err := env.SetPayload(payload)
		assert.Nil(t, err)

		storedPayload := env.GetPayload()
		layout, ok := storedPayload.(Layout)
		assert.True(t, ok, "payload must be layout")
		assert.Equal(t, payload, layout)
	})

	t.Run("get link payload", func(t *testing.T) {
		env := &Envelope{}

		payload := Link{
			Type:        "link",
			Name:        "test",
			Materials:   map[string]HashObj{},
			Products:    map[string]HashObj{},
			ByProducts:  map[string]any{},
			Environment: map[string]any{},
			Command:     []string{},
		}
		err := env.SetPayload(payload)
		assert.Nil(t, err)

		storedPayload := env.GetPayload()
		link, ok := storedPayload.(Link)
		assert.True(t, ok, "payload must be link")
		assert.Equal(t, payload, link)
	})

	t.Run("get overwritten payload", func(t *testing.T) {
		env := &Envelope{}

		payload := Link{
			Type:        "link",
			Name:        "test",
			Materials:   map[string]HashObj{},
			Products:    map[string]HashObj{},
			ByProducts:  map[string]any{},
			Environment: map[string]any{},
			Command:     []string{},
		}
		err := env.SetPayload(payload)
		assert.Nil(t, err)

		storedPayload := env.GetPayload()
		link, ok := storedPayload.(Link)
		assert.True(t, ok, "payload must be link")
		assert.Equal(t, payload, link)

		newPayload := Layout{
			Type:    "layout",
			Steps:   []Step{},
			Inspect: []Inspection{},
			Keys:    map[string]Key{},
			Expires: "2030-01-01T12:00:00Z",
			Readme:  "readme",
		}

		err = env.SetPayload(newPayload)
		assert.Nil(t, err)

		storedPayload = env.GetPayload()
		layout, ok := storedPayload.(Layout)
		assert.True(t, ok, "payload must be layout")
		assert.Equal(t, newPayload, layout)
	})
}

func TestEnvelopeDump(t *testing.T) {
	env := &Envelope{
		envelope: &dsse.Envelope{
			PayloadType: PayloadType,
			Payload:     "eyJfdHlwZSI6ICJsYXlvdXQiLCAiZXhwaXJlcyI6ICIyMDMwLTExLTE4VDE2OjA2OjM2WiIsICJpbnNwZWN0IjogW3siX3R5cGUiOiAiaW5zcGVjdGlvbiIsICJleHBlY3RlZF9tYXRlcmlhbHMiOiBbWyJNQVRDSCIsICJmb28udGFyLmd6IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJwYWNrYWdlIl0sIFsiRElTQUxMT1ciLCAiZm9vLnRhci5neiJdXSwgImV4cGVjdGVkX3Byb2R1Y3RzIjogW1siTUFUQ0giLCAiZm9vLnB5IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJ3cml0ZS1jb2RlIl0sIFsiRElTQUxMT1ciLCAiZm9vLnB5Il1dLCAibmFtZSI6ICJ1bnRhciIsICJydW4iOiBbInRhciIsICJ4ZnoiLCAiZm9vLnRhci5neiJdfV0sICJrZXlzIjogeyJiN2Q2NDNkZWMwYTA1MTA5NmVlNWQ4NzIyMWI1ZDkxYTMzZGFhNjU4Njk5ZDMwOTAzZTFjZWZiOTBjNDE4NDAxIjogeyJrZXlpZCI6ICJiN2Q2NDNkZWMwYTA1MTA5NmVlNWQ4NzIyMWI1ZDkxYTMzZGFhNjU4Njk5ZDMwOTAzZTFjZWZiOTBjNDE4NDAxIiwgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsic2hhMjU2IiwgInNoYTUxMiJdLCAia2V5dHlwZSI6ICJyc2EiLCAia2V5dmFsIjogeyJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJvakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBWThBTUlJQmlnS0NBWUVBeUNUaWs5ODk1M2hLbDYrQjZuNWxcbjhEVklEd0RudnJKZnBhc2JKMytSdzY2WWNhd09aaW5ScE14UFRxV0JLczdzUm9wN2pxc1FOY3NsVW9JWkxyWFBcbnIzZm9QSEY0NTVUbHJxUFZmQ1ppRlErTzRDYWZ4V09CNG1MMU5kZHZwRlhURWptVWl3RnJyTDdQY3ZRS01iWXpcbmVVSEg0dEg5TU56cUtXYmJKb2VrQnNEcENESXhwMU5iZ2l2R0JLd2pSR2EyODFzQ2xLZ3BkMFEwZWJsK1JUY1RcbnZwZlpWRGJYYXpRN1ZxWmtpZHQ3Z2VXcTJCaWRPWFpwL2Nqb1h5Vm5lS3gvZ1lpT1V2OHg5NHN2UU16U0VodzJcbkxGTVEwNEExS25HbjFqeE8zNS9mZDYvT1czMm5qeVdzOTZSS3U5VVFWYWNZSHNRZnNBQ1BXd21WcWduWC9zcDVcbnVqbHZTRGp5Zlp1N2M1eVVRMmFzWWZRUEx2bmpHK3U3UWNCdWtHZjhoQWZWZ3NlenpYOVFQaUszNUJLRGdCVS9cblZrNDNyaUpzMTY1VEpHWUdWdUxVaElFaEhnaVF0d284cFVUSlM1bnBFZTVYTUR1Wm9pZ2hOZHpvV1kybmZzQmZcbnA4MzQ4azZ2SnRETUIwOTMvdDZWOXNUR1lRY1NiZ0tQeUVRbzVQazZXZDRaQWdNQkFBRT1cbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSJ9LCAic2NoZW1lIjogInJzYXNzYS1wc3Mtc2hhMjU2In0sICJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIjogeyJrZXlpZCI6ICJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIiwgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsic2hhMjU2IiwgInNoYTUxMiJdLCAia2V5dHlwZSI6ICJyc2EiLCAia2V5dmFsIjogeyJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeGN6OUF1Y05ia0piUXB3VEhsRUhcblJCK2grTWtZS1FqdzA2SWdaOFRYbFhHcXA1cGR3VEhJNW41aUZvbDAvcmtzbWlaeGF0SHdodGg3cnlZTkMzVmtcbjlnL0xBczlFNjB5V3l0aVNnVjkzRUt2NjVibWhZcWlTQWtKZHlhUEt2Q2I3Y0c5NzlCNGUrSFZwZFZ4NnM3RXhcbklvYURSWWNYM1ZJdDZWMjUvU1F6NWlOVWVWbGIrK1F0U2ZRRkVmM2xIYXVvRmhXWm9Dc2UyNG5XdFlabyszVXRcbnVUbXh5Z3A3dFUvOU5tWWIyQlhFZlVDZGdqb0NRMVVzRkxCUVE0aGFJZEpOT3RSRmw4S05ZMDl6Yk1VaWpLSWVcblgwWnZnVDg3N0xVdE15eWRLUEVvMDQvdTNERXI5WmJhL1NrSHc0M2pZRS9vamxYZWlrNXVWakxTcjNzSkxEU1Bcbkh3SURBUUFCXG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0ifSwgInNjaGVtZSI6ICJyc2Fzc2EtcHNzLXNoYTI1NiJ9fSwgInJlYWRtZSI6ICIiLCAic3RlcHMiOiBbeyJfdHlwZSI6ICJzdGVwIiwgImV4cGVjdGVkX2NvbW1hbmQiOiBbXSwgImV4cGVjdGVkX21hdGVyaWFscyI6IFtdLCAiZXhwZWN0ZWRfcHJvZHVjdHMiOiBbWyJBTExPVyIsICJmb28ucHkiXV0sICJuYW1lIjogIndyaXRlLWNvZGUiLCAicHVia2V5cyI6IFsiYjdkNjQzZGVjMGEwNTEwOTZlZTVkODcyMjFiNWQ5MWEzM2RhYTY1ODY5OWQzMDkwM2UxY2VmYjkwYzQxODQwMSJdLCAidGhyZXNob2xkIjogMX0sIHsiX3R5cGUiOiAic3RlcCIsICJleHBlY3RlZF9jb21tYW5kIjogWyJ0YXIiLCAiemN2ZiIsICJmb28udGFyLmd6IiwgImZvby5weSJdLCAiZXhwZWN0ZWRfbWF0ZXJpYWxzIjogW1siTUFUQ0giLCAiZm9vLnB5IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJ3cml0ZS1jb2RlIl0sIFsiRElTQUxMT1ciLCAiKiJdXSwgImV4cGVjdGVkX3Byb2R1Y3RzIjogW1siQUxMT1ciLCAiZm9vLnRhci5neiJdLCBbIkFMTE9XIiwgImZvby5weSJdXSwgIm5hbWUiOiAicGFja2FnZSIsICJwdWJrZXlzIjogWyJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIl0sICJ0aHJlc2hvbGQiOiAxfV19",
			Signatures: []dsse.Signature{
				{
					KeyID: "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680",
					Sig:   "m5eJXn/whrDdgJ94u8pYI5BVUnQGpjkTQkhqjrB1nD0XFQ6+doHZLCZRzWwxO670vhZMxhLP6kPl5CK4yL42niG0+09tzKlAOsVAMnTsleJNkn6wy5SHsWBTELqlTvDyNs81FdhdEonvbm2zrQs6a0qstMVabBpkwPNVNf0jK463PAFU9jXwFV2dPDdqUCKoy7TcDi6kZOeNmXNANXhV5PGY6wh+FNAuxTWnTHMKGLiSnSyao92y8yKu+fxy4KoZkm923IQyYxSRNZT4DYTnehYDL3tJnDebWRssknZyZIuq9+aTAh7ospe8+Ak4CurdtAHjR7QBugR5iwCUIBKuww==",
				},
			},
		},
	}

	existing := "demo.dsse.layout"
	tmp := existing + ".tmp"

	if err := env.Dump(tmp); err != nil {
		t.Error(err)
	}

	savedMetadata, err := LoadMetadata(existing)
	if err != nil {
		t.Error(err)
	}

	envelope, ok := savedMetadata.(*Envelope)
	assert.True(t, ok, "saved metadata must be envelope")
	assert.Equal(t, env.envelope, envelope.envelope)

	tmpMetadata, err := LoadMetadata(tmp)
	if err != nil {
		t.Error(err)
	}

	envelope, ok = tmpMetadata.(*Envelope)
	assert.True(t, ok, "tmp metadata must be envelope")
	assert.Equal(t, env.envelope, envelope.envelope)
}

func TestEnvelopeVerifySignature(t *testing.T) {
	env, err := LoadMetadata("demo.dsse.layout")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("successful signature verification", func(t *testing.T) {
		var key Key
		if err := key.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			t.Fatal(err)
		}

		err = env.VerifySignature(key)
		assert.Nil(t, err)
	})

	t.Run("fail signature verification", func(t *testing.T) {
		var key Key
		if err := key.LoadKey("carol.pub", "ed25519", []string{"sha256", "sha512"}); err != nil {
			t.Fatal(err)
		}

		err = env.VerifySignature(key)
		assert.NotNil(t, err)
	})

	t.Run("invalid key", func(t *testing.T) {
		key := Key{
			KeyID:   "invalid",
			KeyType: "invalid",
		}

		err := env.VerifySignature(key)
		assert.ErrorIs(t, err, ErrUnsupportedKeyType)
	})
}

func TestEnvelopeSign(t *testing.T) {
	env := &Envelope{
		envelope: &dsse.Envelope{
			PayloadType: PayloadType,
			Payload:     "eyJfdHlwZSI6ICJsYXlvdXQiLCAiZXhwaXJlcyI6ICIyMDMwLTExLTE4VDE2OjA2OjM2WiIsICJpbnNwZWN0IjogW3siX3R5cGUiOiAiaW5zcGVjdGlvbiIsICJleHBlY3RlZF9tYXRlcmlhbHMiOiBbWyJNQVRDSCIsICJmb28udGFyLmd6IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJwYWNrYWdlIl0sIFsiRElTQUxMT1ciLCAiZm9vLnRhci5neiJdXSwgImV4cGVjdGVkX3Byb2R1Y3RzIjogW1siTUFUQ0giLCAiZm9vLnB5IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJ3cml0ZS1jb2RlIl0sIFsiRElTQUxMT1ciLCAiZm9vLnB5Il1dLCAibmFtZSI6ICJ1bnRhciIsICJydW4iOiBbInRhciIsICJ4ZnoiLCAiZm9vLnRhci5neiJdfV0sICJrZXlzIjogeyJiN2Q2NDNkZWMwYTA1MTA5NmVlNWQ4NzIyMWI1ZDkxYTMzZGFhNjU4Njk5ZDMwOTAzZTFjZWZiOTBjNDE4NDAxIjogeyJrZXlpZCI6ICJiN2Q2NDNkZWMwYTA1MTA5NmVlNWQ4NzIyMWI1ZDkxYTMzZGFhNjU4Njk5ZDMwOTAzZTFjZWZiOTBjNDE4NDAxIiwgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsic2hhMjU2IiwgInNoYTUxMiJdLCAia2V5dHlwZSI6ICJyc2EiLCAia2V5dmFsIjogeyJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJvakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBWThBTUlJQmlnS0NBWUVBeUNUaWs5ODk1M2hLbDYrQjZuNWxcbjhEVklEd0RudnJKZnBhc2JKMytSdzY2WWNhd09aaW5ScE14UFRxV0JLczdzUm9wN2pxc1FOY3NsVW9JWkxyWFBcbnIzZm9QSEY0NTVUbHJxUFZmQ1ppRlErTzRDYWZ4V09CNG1MMU5kZHZwRlhURWptVWl3RnJyTDdQY3ZRS01iWXpcbmVVSEg0dEg5TU56cUtXYmJKb2VrQnNEcENESXhwMU5iZ2l2R0JLd2pSR2EyODFzQ2xLZ3BkMFEwZWJsK1JUY1RcbnZwZlpWRGJYYXpRN1ZxWmtpZHQ3Z2VXcTJCaWRPWFpwL2Nqb1h5Vm5lS3gvZ1lpT1V2OHg5NHN2UU16U0VodzJcbkxGTVEwNEExS25HbjFqeE8zNS9mZDYvT1czMm5qeVdzOTZSS3U5VVFWYWNZSHNRZnNBQ1BXd21WcWduWC9zcDVcbnVqbHZTRGp5Zlp1N2M1eVVRMmFzWWZRUEx2bmpHK3U3UWNCdWtHZjhoQWZWZ3NlenpYOVFQaUszNUJLRGdCVS9cblZrNDNyaUpzMTY1VEpHWUdWdUxVaElFaEhnaVF0d284cFVUSlM1bnBFZTVYTUR1Wm9pZ2hOZHpvV1kybmZzQmZcbnA4MzQ4azZ2SnRETUIwOTMvdDZWOXNUR1lRY1NiZ0tQeUVRbzVQazZXZDRaQWdNQkFBRT1cbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSJ9LCAic2NoZW1lIjogInJzYXNzYS1wc3Mtc2hhMjU2In0sICJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIjogeyJrZXlpZCI6ICJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIiwgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsic2hhMjU2IiwgInNoYTUxMiJdLCAia2V5dHlwZSI6ICJyc2EiLCAia2V5dmFsIjogeyJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeGN6OUF1Y05ia0piUXB3VEhsRUhcblJCK2grTWtZS1FqdzA2SWdaOFRYbFhHcXA1cGR3VEhJNW41aUZvbDAvcmtzbWlaeGF0SHdodGg3cnlZTkMzVmtcbjlnL0xBczlFNjB5V3l0aVNnVjkzRUt2NjVibWhZcWlTQWtKZHlhUEt2Q2I3Y0c5NzlCNGUrSFZwZFZ4NnM3RXhcbklvYURSWWNYM1ZJdDZWMjUvU1F6NWlOVWVWbGIrK1F0U2ZRRkVmM2xIYXVvRmhXWm9Dc2UyNG5XdFlabyszVXRcbnVUbXh5Z3A3dFUvOU5tWWIyQlhFZlVDZGdqb0NRMVVzRkxCUVE0aGFJZEpOT3RSRmw4S05ZMDl6Yk1VaWpLSWVcblgwWnZnVDg3N0xVdE15eWRLUEVvMDQvdTNERXI5WmJhL1NrSHc0M2pZRS9vamxYZWlrNXVWakxTcjNzSkxEU1Bcbkh3SURBUUFCXG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0ifSwgInNjaGVtZSI6ICJyc2Fzc2EtcHNzLXNoYTI1NiJ9fSwgInJlYWRtZSI6ICIiLCAic3RlcHMiOiBbeyJfdHlwZSI6ICJzdGVwIiwgImV4cGVjdGVkX2NvbW1hbmQiOiBbXSwgImV4cGVjdGVkX21hdGVyaWFscyI6IFtdLCAiZXhwZWN0ZWRfcHJvZHVjdHMiOiBbWyJBTExPVyIsICJmb28ucHkiXV0sICJuYW1lIjogIndyaXRlLWNvZGUiLCAicHVia2V5cyI6IFsiYjdkNjQzZGVjMGEwNTEwOTZlZTVkODcyMjFiNWQ5MWEzM2RhYTY1ODY5OWQzMDkwM2UxY2VmYjkwYzQxODQwMSJdLCAidGhyZXNob2xkIjogMX0sIHsiX3R5cGUiOiAic3RlcCIsICJleHBlY3RlZF9jb21tYW5kIjogWyJ0YXIiLCAiemN2ZiIsICJmb28udGFyLmd6IiwgImZvby5weSJdLCAiZXhwZWN0ZWRfbWF0ZXJpYWxzIjogW1siTUFUQ0giLCAiZm9vLnB5IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJ3cml0ZS1jb2RlIl0sIFsiRElTQUxMT1ciLCAiKiJdXSwgImV4cGVjdGVkX3Byb2R1Y3RzIjogW1siQUxMT1ciLCAiZm9vLnRhci5neiJdLCBbIkFMTE9XIiwgImZvby5weSJdXSwgIm5hbWUiOiAicGFja2FnZSIsICJwdWJrZXlzIjogWyJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIl0sICJ0aHJlc2hvbGQiOiAxfV19",
			Signatures:  []dsse.Signature{},
		},
	}

	var key Key
	if err := key.LoadKey("carol", "ed25519", []string{"sha256", "sha512"}); err != nil {
		t.Fatal(err)
	}

	t.Run("valid ed25519 key", func(t *testing.T) {
		if err := env.Sign(key); err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6", env.envelope.Signatures[0].KeyID)
		assert.Equal(t, "HeacKZDQD+EIYz1dLJ2NpXxcG70tn62BOzcxnAArFSKJcWIL0qcyzvdtpSJQ0pOyq8lBxMk5nIRO0Kr89SZoBA==", env.envelope.Signatures[0].Sig)
	})

	t.Run("invalid key", func(t *testing.T) {
		key := Key{
			KeyID:   "invalid",
			KeyType: "invalid",
		}

		err := env.Sign(key)
		assert.ErrorIs(t, err, ErrUnsupportedKeyType)
	})

	t.Run("invalid payload", func(t *testing.T) {
		env.envelope.Payload = "abcdef"

		err := env.Sign(key)
		assert.ErrorContains(t, err, "unable to base64 decode payload")
	})
}

func TestEnvelopeGetSignatureForKeyID(t *testing.T) {
	env := &Envelope{
		envelope: &dsse.Envelope{
			PayloadType: PayloadType,
			Payload:     "eyJfdHlwZSI6ICJsYXlvdXQiLCAiZXhwaXJlcyI6ICIyMDMwLTExLTE4VDE2OjA2OjM2WiIsICJpbnNwZWN0IjogW3siX3R5cGUiOiAiaW5zcGVjdGlvbiIsICJleHBlY3RlZF9tYXRlcmlhbHMiOiBbWyJNQVRDSCIsICJmb28udGFyLmd6IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJwYWNrYWdlIl0sIFsiRElTQUxMT1ciLCAiZm9vLnRhci5neiJdXSwgImV4cGVjdGVkX3Byb2R1Y3RzIjogW1siTUFUQ0giLCAiZm9vLnB5IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJ3cml0ZS1jb2RlIl0sIFsiRElTQUxMT1ciLCAiZm9vLnB5Il1dLCAibmFtZSI6ICJ1bnRhciIsICJydW4iOiBbInRhciIsICJ4ZnoiLCAiZm9vLnRhci5neiJdfV0sICJrZXlzIjogeyJiN2Q2NDNkZWMwYTA1MTA5NmVlNWQ4NzIyMWI1ZDkxYTMzZGFhNjU4Njk5ZDMwOTAzZTFjZWZiOTBjNDE4NDAxIjogeyJrZXlpZCI6ICJiN2Q2NDNkZWMwYTA1MTA5NmVlNWQ4NzIyMWI1ZDkxYTMzZGFhNjU4Njk5ZDMwOTAzZTFjZWZiOTBjNDE4NDAxIiwgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsic2hhMjU2IiwgInNoYTUxMiJdLCAia2V5dHlwZSI6ICJyc2EiLCAia2V5dmFsIjogeyJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJvakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBWThBTUlJQmlnS0NBWUVBeUNUaWs5ODk1M2hLbDYrQjZuNWxcbjhEVklEd0RudnJKZnBhc2JKMytSdzY2WWNhd09aaW5ScE14UFRxV0JLczdzUm9wN2pxc1FOY3NsVW9JWkxyWFBcbnIzZm9QSEY0NTVUbHJxUFZmQ1ppRlErTzRDYWZ4V09CNG1MMU5kZHZwRlhURWptVWl3RnJyTDdQY3ZRS01iWXpcbmVVSEg0dEg5TU56cUtXYmJKb2VrQnNEcENESXhwMU5iZ2l2R0JLd2pSR2EyODFzQ2xLZ3BkMFEwZWJsK1JUY1RcbnZwZlpWRGJYYXpRN1ZxWmtpZHQ3Z2VXcTJCaWRPWFpwL2Nqb1h5Vm5lS3gvZ1lpT1V2OHg5NHN2UU16U0VodzJcbkxGTVEwNEExS25HbjFqeE8zNS9mZDYvT1czMm5qeVdzOTZSS3U5VVFWYWNZSHNRZnNBQ1BXd21WcWduWC9zcDVcbnVqbHZTRGp5Zlp1N2M1eVVRMmFzWWZRUEx2bmpHK3U3UWNCdWtHZjhoQWZWZ3NlenpYOVFQaUszNUJLRGdCVS9cblZrNDNyaUpzMTY1VEpHWUdWdUxVaElFaEhnaVF0d284cFVUSlM1bnBFZTVYTUR1Wm9pZ2hOZHpvV1kybmZzQmZcbnA4MzQ4azZ2SnRETUIwOTMvdDZWOXNUR1lRY1NiZ0tQeUVRbzVQazZXZDRaQWdNQkFBRT1cbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSJ9LCAic2NoZW1lIjogInJzYXNzYS1wc3Mtc2hhMjU2In0sICJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIjogeyJrZXlpZCI6ICJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIiwgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsic2hhMjU2IiwgInNoYTUxMiJdLCAia2V5dHlwZSI6ICJyc2EiLCAia2V5dmFsIjogeyJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeGN6OUF1Y05ia0piUXB3VEhsRUhcblJCK2grTWtZS1FqdzA2SWdaOFRYbFhHcXA1cGR3VEhJNW41aUZvbDAvcmtzbWlaeGF0SHdodGg3cnlZTkMzVmtcbjlnL0xBczlFNjB5V3l0aVNnVjkzRUt2NjVibWhZcWlTQWtKZHlhUEt2Q2I3Y0c5NzlCNGUrSFZwZFZ4NnM3RXhcbklvYURSWWNYM1ZJdDZWMjUvU1F6NWlOVWVWbGIrK1F0U2ZRRkVmM2xIYXVvRmhXWm9Dc2UyNG5XdFlabyszVXRcbnVUbXh5Z3A3dFUvOU5tWWIyQlhFZlVDZGdqb0NRMVVzRkxCUVE0aGFJZEpOT3RSRmw4S05ZMDl6Yk1VaWpLSWVcblgwWnZnVDg3N0xVdE15eWRLUEVvMDQvdTNERXI5WmJhL1NrSHc0M2pZRS9vamxYZWlrNXVWakxTcjNzSkxEU1Bcbkh3SURBUUFCXG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0ifSwgInNjaGVtZSI6ICJyc2Fzc2EtcHNzLXNoYTI1NiJ9fSwgInJlYWRtZSI6ICIiLCAic3RlcHMiOiBbeyJfdHlwZSI6ICJzdGVwIiwgImV4cGVjdGVkX2NvbW1hbmQiOiBbXSwgImV4cGVjdGVkX21hdGVyaWFscyI6IFtdLCAiZXhwZWN0ZWRfcHJvZHVjdHMiOiBbWyJBTExPVyIsICJmb28ucHkiXV0sICJuYW1lIjogIndyaXRlLWNvZGUiLCAicHVia2V5cyI6IFsiYjdkNjQzZGVjMGEwNTEwOTZlZTVkODcyMjFiNWQ5MWEzM2RhYTY1ODY5OWQzMDkwM2UxY2VmYjkwYzQxODQwMSJdLCAidGhyZXNob2xkIjogMX0sIHsiX3R5cGUiOiAic3RlcCIsICJleHBlY3RlZF9jb21tYW5kIjogWyJ0YXIiLCAiemN2ZiIsICJmb28udGFyLmd6IiwgImZvby5weSJdLCAiZXhwZWN0ZWRfbWF0ZXJpYWxzIjogW1siTUFUQ0giLCAiZm9vLnB5IiwgIldJVEgiLCAiUFJPRFVDVFMiLCAiRlJPTSIsICJ3cml0ZS1jb2RlIl0sIFsiRElTQUxMT1ciLCAiKiJdXSwgImV4cGVjdGVkX3Byb2R1Y3RzIjogW1siQUxMT1ciLCAiZm9vLnRhci5neiJdLCBbIkFMTE9XIiwgImZvby5weSJdXSwgIm5hbWUiOiAicGFja2FnZSIsICJwdWJrZXlzIjogWyJkM2ZmZDEwODY5MzhiMzY5ODYxOGFkZjA4OGJmMTRiMTNkYjRjOGFlMTllNGU3OGQ3M2RhNDllZTg4NDkyNzEwIl0sICJ0aHJlc2hvbGQiOiAxfV19",
			Signatures: []dsse.Signature{
				{
					KeyID: "testKeyID1",
					Sig:   "dummy sig 1",
				},
				{
					KeyID: "testKeyID2",
					Sig:   "dummy sig 2",
				},
			},
		},
	}

	sig, err := env.GetSignatureForKeyID("testKeyID1")
	assert.Nil(t, err)
	assert.Equal(t, Signature{KeyID: "testKeyID1", Sig: "dummy sig 1"}, sig)

	sig, err = env.GetSignatureForKeyID("testKeyID2")
	assert.Nil(t, err)
	assert.Equal(t, Signature{KeyID: "testKeyID2", Sig: "dummy sig 2"}, sig)

	_, err = env.GetSignatureForKeyID("unknown")
	assert.ErrorContains(t, err, "no signature found for key")
}
