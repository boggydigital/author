package author

import "errors"

var (
	ErrUsernameExists           = errors.New("username already exists")
	ErrUsernameNotFound         = errors.New("username not found")
	ErrUsernamePasswordMissing  = errors.New("username is missing a password")
	ErrUsernamePasswordMismatch = errors.New("username password mismatch")
	ErrSessionExpired           = errors.New("session expired")
	ErrSessionNotValid          = errors.New("session is not valid")
	ErrInsufficientPermissions  = errors.New("insufficient permissions")
)

func IsNotAuthenticated(err error) bool {
	return errors.Is(err, ErrUsernamePasswordMismatch)
}
