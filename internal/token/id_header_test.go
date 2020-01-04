package token

import (
	"encoding/base64"
	"testing"
)

// lets try to process simple cases
var vectorParseHeaderTest = []struct {
	token string
	want  error
}{
	{"{\"alg\":\"RS256\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\",\"typ\":\"JWT\"}", nil},    // VALID
	{"{\"alg\":\"RS256\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\"}", nil},                    // VALID
	{"{\"alg\":\"RS384\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\"}", nil},                    // VALID
	{"{\"alg\":\"RS512\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\"}", nil},                    // VALID
	{"{\"alg\":\"RS1024\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\"}", ErrParse},              // invalid alg
	{"{\"alg\":\"RS256\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\",\"typ\":JWT\"}", ErrParse}, // invalid JSON
	{"", ErrParse},   // empty
	{"{}", ErrParse}, // empty json
	{"{\"alg\":\"\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\",\"typ\":\"JWT\"}", ErrParse},     // empty alg
	{"{\"alg\":\"RS256\",\"kid\":\"\",\"typ\":\"JWT\"}", ErrParse},                                        // empty kid
	{"{\"alg\":\"S256\",\"kid\":\"47456b8069e4365e517ca5e29757d1a9efa567ba\",\"typ\":\"JWT\"}", ErrParse}, // invalid alg
	//{"eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3NDU2YjgwNjllNDM2NWU1MTdjYTVlMjk3NTdkMWE5ZWZhNTY3YmEiLCJ0eXAiOiJKV1QifQ", nil},
}

func TestParseHeader(t *testing.T) {
	for i, v := range vectorParseHeaderTest {
		token := base64.RawURLEncoding.EncodeToString([]byte(v.token))
		_, err := ParseHeader(token)
		if v.want != err {
			t.Fatalf("test #%d failed error: %v vs expected: %v\n", i, err, v.want)
		}
	}
}
