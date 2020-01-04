package token

import (
	"encoding/base64"
	"testing"
)

var vectorParseClaimsTest = []struct {
	token string
	want  error
}{
	{`{"iss":"https://accounts.google.com","azp":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","aud":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","sub":"112309970368563138965","email":"arizotatsuo@gmail.com","email_verified":true,"at_hash":"25Z8_y2wxGUHoWa9gTmfBw","nonce":"cd0f8776-61a7-45e5-888c-4b3e95767600","name":"arizo to","picture":"https://lh4.googleusercontent.com/-2XuiQez2UCo/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rc-O768GynNKIO15ZaeVlpZAZnWaA/s96-c/photo.jpg","given_name":"arizo","family_name":"to","locale":"en","iat":1577755963,"exp":1577759563}`, nil}, // Valid
	{`{"iss":"","azp":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","aud":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","sub":"112309970368563138965","email":"arizotatsuo@gmail.com","email_verified":true,"at_hash":"25Z8_y2wxGUHoWa9gTmfBw","nonce":"cd0f8776-61a7-45e5-888c-4b3e95767600","name":"arizo to","picture":"https://lh4.googleusercontent.com/-2XuiQez2UCo/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rc-O768GynNKIO15ZaeVlpZAZnWaA/s96-c/photo.jpg","given_name":"arizo","family_name":"to","locale":"en","iat":1577755963,"exp":1577759563}`, ErrParse},                       // empty issuer
	{`{"iss":"https://accounts.google.com","azp":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","aud":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","sub":"","email":"arizotatsuo@gmail.com","email_verified":true,"at_hash":"25Z8_y2wxGUHoWa9gTmfBw","nonce":"cd0f8776-61a7-45e5-888c-4b3e95767600","name":"arizo to","picture":"https://lh4.googleusercontent.com/-2XuiQez2UCo/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rc-O768GynNKIO15ZaeVlpZAZnWaA/s96-c/photo.jpg","given_name":"arizo","family_name":"to","locale":"en","iat":1577755963,"exp":1577759563}`, ErrParse},                 // empty sub
	{`{"iss":"https://accounts.google.com","azp":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","aud":"","sub":"112309970368563138965","email":"arizotatsuo@gmail.com","email_verified":true,"at_hash":"25Z8_y2wxGUHoWa9gTmfBw","nonce":"cd0f8776-61a7-45e5-888c-4b3e95767600","name":"arizo to","picture":"https://lh4.googleusercontent.com/-2XuiQez2UCo/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rc-O768GynNKIO15ZaeVlpZAZnWaA/s96-c/photo.jpg","given_name":"arizo","family_name":"to","locale":"en","iat":1577755963,"exp":1577759563}`, ErrParse},                                                                    // empty aud
	{`{"iss":"https://accounts.google.com","azp":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","aud":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","sub":"112309970368563138965","email":"arizotatsuo@gmail.com","email_verified":true,"at_hash":"25Z8_y2wxGUHoWa9gTmfBw","nonce":"cd0f8776-61a7-45e5-888c-4b3e95767600","name":"arizo to","picture":"https://lh4.googleusercontent.com/-2XuiQez2UCo/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rc-O768GynNKIO15ZaeVlpZAZnWaA/s96-c/photo.jpg","given_name":"arizo","family_name":"to","locale":"en","iat":1577755963,"exp":}`, ErrParse},      // exp == 0
	{`{"iss":"https://accounts.google.com","azp":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","aud":"118314873199-nmb36i0cqsjsj2d5k6g1v251bhq2cj4s.apps.googleusercontent.com","sub":"112309970368563138965","email":"arizotatsuo@gmail.com","email_verified":true,"at_hash":"25Z8_y2wxGUHoWa9gTmfBw","nonce":"cd0f8776-61a7-45e5-888c-4b3e95767600","name":"arizo to","picture":"https://lh4.googleusercontent.com/-2XuiQez2UCo/AAAAAAAAAAI/AAAAAAAAAAA/ACHi3rc-O768GynNKIO15ZaeVlpZAZnWaA/s96-c/photo.jpg","given_name":"arizo","family_name":"to","locale":"en","iat":0,"exp":1577759563}`, ErrParse},     // iat == 0
}

func TestParseClaims(t *testing.T) {
	for i, v := range vectorParseClaimsTest {
		token := base64.RawURLEncoding.EncodeToString([]byte(v.token))
		_, err := ParseClaims(token)
		if v.want != err {
			t.Fatalf("test #%d failed error: %v vs expected: %v\n", i, err, v.want)
		}
	}
}
