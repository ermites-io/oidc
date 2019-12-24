// +build  go1.12

package token

import "fmt"

// signature
type Signature struct {
	// raw: base64
	Raw []byte

	// debase64 signature
	Blob []byte
}

func (s Signature) String() string {
	return fmt.Sprintf("SIG: '%s'\n", s.Raw)
}

func (s Signature) GetBlob() []byte {
	return s.Blob
}
