package securegrpc

import "errors"

var (
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrTLSError      = errors.New("TLS error")
	ErrACLError      = errors.New("ACL error")
)
