package author

import (
	"time"
)

type Authenticator interface {
	HasUser(username string) (bool, error)
	CreateUser(username, password string) error
	CutUser(username, password string) error
	UpdatePassword(username, currentPassword, newPassword string) error
	SetRole(username, password, role string) error
	GetUserRoles() (map[string][]string, error)
	AuthenticateUser(username, password string) error

	CreateSession(username, password string) (string, error)
	SessionExpires(session string) (time.Time, error)
	AuthenticateSession(session string) error
	CutSession(session string) error
	CutUserSessions(username string) error
	GetSessionPermissions(session string) ([]Permission, error)
	MustHaveSessionPermissions(session string, requiredPermissions ...Permission) error
}
