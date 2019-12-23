// +build go1.12

package jwk

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrParse       = Error("parse error")
	ErrUnsupported = Error("unsupported format")
)
