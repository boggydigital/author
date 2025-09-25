package author

const (
	UsernamePasswordProperty = "username-password"
	UsernameRoleProperty     = "username-role"
	UsernameSessionProperty  = "username-session"
	SessionCreatedProperty   = "session-created"
)

func AllProperties() []string {
	return []string{
		UsernamePasswordProperty,
		UsernameRoleProperty,
		UsernameSessionProperty,
		SessionCreatedProperty,
	}
}
