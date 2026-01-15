package author

import (
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/boggydigital/redux"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultSessionDurationDays = 90
)

type authenticator struct {
	rdx             redux.Writeable
	rolePermissions map[string][]Permission
}

func NewAuthenticator(dir string, rolePermissions map[string][]Permission) (Authenticator, error) {

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err = os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	rdx, err := redux.NewWriter(dir, AllProperties()...)
	if err != nil {
		return nil, err
	}

	a := &authenticator{
		rdx:             rdx,
		rolePermissions: rolePermissions,
	}

	return a, nil
}

func (a *authenticator) HasUser(username string) (bool, error) {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return false, err
	}

	return a.rdx.HasKey(UsernamePasswordProperty, username), nil
}

func (a *authenticator) CreateUser(username, password string) error {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return err
	}

	if a.rdx.HasKey(UsernamePasswordProperty, username) {
		return ErrUsernameExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return a.rdx.AddValues(UsernamePasswordProperty, username, string(hashedPassword))
}

func (a *authenticator) UpdatePassword(username, currentPassword, newPassword string) error {

	if err := a.AuthenticateUser(username, currentPassword); err != nil {
		return err
	}

	if !a.rdx.HasKey(UsernamePasswordProperty, username) {
		return ErrUsernameNotFound
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return a.rdx.ReplaceValues(UsernamePasswordProperty, username, string(hashedNewPassword))
}

func (a *authenticator) CutUser(username, password string) error {

	if err := a.AuthenticateUser(username, password); err != nil {
		return err
	}

	if err := a.rdx.CutKeys(UsernamePasswordProperty, username); err != nil {
		return err
	}

	if sessions, ok := a.rdx.GetAllValues(UsernameSessionProperty, username); ok && len(sessions) > 0 {
		if err := a.rdx.CutKeys(SessionCreatedProperty, sessions...); err != nil {
			return err
		}
	}

	if err := a.rdx.CutKeys(UsernameSessionProperty, username); err != nil {
		return err
	}

	return a.rdx.CutKeys(UsernameRoleProperty, username)
}

func (a *authenticator) SetRole(username, password, role string) error {

	if err := a.AuthenticateUser(username, password); err != nil {
		return err
	}

	return a.rdx.ReplaceValues(UsernameRoleProperty, username, role)
}

func (a *authenticator) GetUserRoles() (map[string][]string, error) {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return nil, err
	}

	userRoles := make(map[string][]string)

	for username := range a.rdx.Keys(UsernameRoleProperty) {
		if roles, ok := a.rdx.GetAllValues(UsernameRoleProperty, username); ok && len(roles) > 0 {
			userRoles[username] = roles
		}
	}

	return userRoles, nil
}

func (a *authenticator) AuthenticateUser(username, password string) error {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return err
	}

	if !a.rdx.HasKey(UsernamePasswordProperty, username) {
		return ErrUsernameNotFound
	}

	if ph, ok := a.rdx.GetLastVal(UsernamePasswordProperty, username); ok {

		if err := bcrypt.CompareHashAndPassword([]byte(ph), []byte(password)); err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return ErrUsernamePasswordMismatch
			} else {
				return err
			}
		}

	} else {
		return ErrUsernamePasswordMissing
	}

	return nil
}

func (a *authenticator) CreateSession(username, password string) (string, error) {

	if err := a.AuthenticateUser(username, password); err != nil {
		return "", err
	}

	if existingSession, ok := a.rdx.GetLastVal(UsernameSessionProperty, username); ok && existingSession != "" {
		sessionExpires, err := a.SessionExpires(existingSession)
		if err != nil {
			return "", err
		}
		if isUtcFuture(sessionExpires) {
			return existingSession, nil
		}
	}

	session := rand.Text()

	if err := a.rdx.AddValues(UsernameSessionProperty, username, session); err != nil {
		return "", err
	}

	if err := a.rdx.ReplaceValues(SessionCreatedProperty, session, time.Now().UTC().Format(http.TimeFormat)); err != nil {
		return "", err
	}

	return session, nil
}

func (a *authenticator) SessionExpires(session string) (time.Time, error) {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return time.Time{}, err
	}

	if scs, ok := a.rdx.GetLastVal(SessionCreatedProperty, session); ok && scs != "" {

		var sct time.Time
		sct, err = http.ParseTime(scs)
		if err != nil {
			return time.Time{}, err
		}

		sessionExpires := sct.Add(defaultSessionDurationDays * time.Hour * 24)
		return sessionExpires, nil

	}

	return time.Time{}, ErrSessionNotValid
}

func (a *authenticator) AuthenticateSession(session string) error {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return err
	}

	sessionExpires, err := a.SessionExpires(session)
	if err != nil {
		return err
	}

	// that's the only successful condition, otherwise the session is not valid
	if isUtcFuture(sessionExpires) {
		return nil
	} else {
		if err = a.CutSession(session); err != nil {
			return err
		}
		return ErrSessionExpired
	}
}

func isUtcFuture(t time.Time) bool {
	if time.Now().UTC().Before(t) {
		return true
	} else {
		return false
	}
}

func (a *authenticator) CutSession(session string) error {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return err
	}

	query := map[string][]string{UsernameSessionProperty: {session}}

	for username := range a.rdx.Match(query, redux.FullMatch) {
		if err = a.rdx.CutValues(UsernameSessionProperty, username, session); err != nil {
			return err
		}
	}

	return a.rdx.CutKeys(SessionCreatedProperty, session)
}

func (a *authenticator) CutUserSessions(username string) error {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return err
	}

	if userSessions, ok := a.rdx.GetAllValues(UsernameSessionProperty, username); ok {
		if err = a.rdx.CutKeys(SessionCreatedProperty, userSessions...); err != nil {
			return err
		}
	}

	return a.rdx.CutKeys(UsernameSessionProperty, username)
}

func (a *authenticator) GetSessionPermissions(session string) ([]Permission, error) {

	var err error
	a.rdx, err = a.rdx.RefreshWriter()
	if err != nil {
		return nil, err
	}

	query := map[string][]string{UsernameSessionProperty: {session}}

	for username := range a.rdx.Match(query, redux.FullMatch) {

		permissions := make([]Permission, 0)

		if roles, ok := a.rdx.GetAllValues(UsernameRoleProperty, username); ok {

			for _, role := range roles {
				if perms, sure := a.rolePermissions[role]; sure {
					permissions = append(permissions, perms...)
				}
			}

		}

		return permissions, nil
	}

	return nil, nil
}

func (a *authenticator) MustHaveSessionPermissions(session string, requiredPermissions ...Permission) error {

	if len(requiredPermissions) == 0 {
		return nil
	}

	sessionPermissions, err := a.GetSessionPermissions(session)
	if err != nil {
		return err
	}

	for _, pm := range requiredPermissions {
		if !slices.Contains(sessionPermissions, pm) {
			return ErrInsufficientPermissions
		}
	}

	return nil
}
