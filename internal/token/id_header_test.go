package token

import "testing"

// lets try to process simple cases
var vectorParseHeaderTest = []struct {
	token string
	want  error
}{
	{"eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3NDU2YjgwNjllNDM2NWU1MTdjYTVlMjk3NTdkMWE5ZWZhNTY3YmEiLCJ0eXAiOiJKV1QifQ", nil},
}

func TestParseHeader(t *testing.T) {
	for i, v := range vectorParseHeaderTest {
		_, err := ParseHeader(v.token)
		if v.want != err {
			t.Fatalf("test #%d failed error: %v vs expected: %v\n", i, err, v.want)
		}
	}
}
