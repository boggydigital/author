package author

const (
	UsernamePasswordProperty = "username-password"
	UsernameRoleProperty     = "username-role"
	UsernameSessionProperty  = "username-session"
)

func AllProperties() []string {
	return []string{
		UsernamePasswordProperty,
		UsernameRoleProperty,
		UsernameSessionProperty,
	}
}
