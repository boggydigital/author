package author

const (
	UsernamePasswordProperty = "username-password"
	UsernameRoleProperty     = "username-role"
	UsernameSessionProperty  = "username-session"
	SessionStartedProperty   = "session-started"
)

func AllProperties() []string {
	return []string{
		UsernamePasswordProperty,
		UsernameRoleProperty,
		UsernameSessionProperty,
		SessionStartedProperty,
	}
}
