// +build go1.12

package token

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrParse = Error("parse error")
)
