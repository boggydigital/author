package author

type Authenticator interface {
	HasUser(username string) bool
	CreateUser(username, password string) error
	CutUser(username, password string) error
	GrantRole(username, password, role string) error
	GetUserRoles() map[string][]string
	AuthenticateUser(username, password string) error

	CreateSession(username, password string) (string, error)
	AuthenticateSession(session string) error
	CutSession(session string) error
	CutUserSessions(username string) error
	GetSessionPermissions(session string) ([]Permission, error)
	MustHaveSessionPermissions(session string, requiredPermissions ...Permission) error
}
