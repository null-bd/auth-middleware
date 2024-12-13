package authmiddleware

import "errors"

var (
    ErrInvalidToken        = errors.New("invalid token")
    ErrExpiredToken        = errors.New("token has expired")
    ErrInsufficientScope   = errors.New("insufficient scope")
    ErrMissingToken        = errors.New("missing token")
    ErrInvalidConfig       = errors.New("invalid configuration")
    ErrServiceUnavailable  = errors.New("auth service unavailable")
)
