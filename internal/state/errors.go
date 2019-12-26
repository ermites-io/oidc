// +build go1.12

package state

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrParse        = Error("parse error")
	ErrUnsupported  = Error("unsupported format")
	ErrInvalid      = Error("invalid input")
	ErrInvalidState = Error("invalid state")
	ErrNetwork      = Error("network error")
)
