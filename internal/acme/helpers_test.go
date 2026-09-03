package acme

import "testing"

// TestParseTXTAnswers ensures DoH TXT values are returned unquoted so they match
// the raw DNS-01 challenge value (the "DNS 尚未传播" loop regression).
func TestParseTXTAnswers(t *testing.T) {
	answers := []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	}{
		{Type: 16, Data: `"GBBRzZWDedakFpN5keTgphFnBA43WRQTBGCdT2bcAIE"`}, // quoted TXT (cloudflare-dns.com style)
		{Type: 16, Data: `"ImxoI-kVRNkEuMdeJn6bq4tKrK3o44_8kLyEd6o0FgY"`}, // second value for same name
		{Type: 16, Data: "plain-no-quotes"},                               // some resolvers omit quotes
		{Type: 1, Data: `"not-a-txt-record"`},                             // type != 16 must be ignored
	}
	got := parseTXTAnswers(answers)
	want := []string{
		"GBBRzZWDedakFpN5keTgphFnBA43WRQTBGCdT2bcAIE",
		"ImxoI-kVRNkEuMdeJn6bq4tKrK3o44_8kLyEd6o0FgY",
		"plain-no-quotes",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("value[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestContainsMatchesRawValue reproduces the original failure path: a quoted
// value parsed to its unquoted form must equal the raw challenge value.
func TestContainsMatchesRawValue(t *testing.T) {
	vals := parseTXTAnswers([]struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	}{
		{Type: 16, Data: `"GBBRzZWDedakFpN5keTgphFnBA43WRQTBGCdT2bcAIE"`},
	})
	if !contains(vals, "GBBRzZWDedakFpN5keTgphFnBA43WRQTBGCdT2bcAIE") {
		t.Fatalf("contains returned false for raw value; quoted data was not stripped")
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		name string
		vals []string
		want string
		out  bool
	}{
		{name: "exact", vals: []string{"a", "b"}, want: "b", out: true},
		{name: "absent", vals: []string{"a", "b"}, want: "c", out: false},
		{name: "empty", vals: nil, want: "a", out: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := contains(c.vals, c.want); got != c.out {
				t.Errorf("contains(%v, %q) = %v, want %v", c.vals, c.want, got, c.out)
			}
		})
	}
}
