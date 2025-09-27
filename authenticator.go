package author

import (
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/boggydigital/redux"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultSessionDurationDays = 90
)

type Authenticator struct {
	rdx             redux.Writeable
	rolePermissions map[string][]Permission
}

func NewAuthenticator(dir string, rolePermissions map[string][]Permission) (*Authenticator, error) {

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

	a := &Authenticator{
		rdx:             rdx,
		rolePermissions: rolePermissions,
	}

	return a, nil
}

func (a *Authenticator) HasUser(username string) bool {
	return a.rdx.HasKey(UsernamePasswordProperty, username)
}

func (a *Authenticator) CreateUser(username, password string) error {

	if a.rdx.HasKey(UsernamePasswordProperty, username) {
		return ErrUsernameExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return a.rdx.AddValues(UsernamePasswordProperty, username, string(hashedPassword))
}

func (a *Authenticator) CutUser(username, password string) error {

	if err := a.Authenticate(username, password); err != nil {
		return err
	}

	if err := a.rdx.CutKeys(UsernamePasswordProperty, username); err != nil {
		return err
	}

	return a.rdx.CutKeys(UsernameRoleProperty, username)
}

func (a *Authenticator) SetRole(username, password, role string) error {

	if err := a.Authenticate(username, password); err != nil {
		return err
	}

	return a.rdx.AddValues(UsernameRoleProperty, username, role)
}

func (a *Authenticator) GetUserRoles() map[string][]string {
	userRoles := make(map[string][]string)

	for username := range a.rdx.Keys(UsernameRoleProperty) {
		if roles, ok := a.rdx.GetAllValues(UsernameRoleProperty, username); ok && len(roles) > 0 {
			userRoles[username] = roles
		}
	}

	return userRoles
}

func (a *Authenticator) Authenticate(username, password string) error {

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

func (a *Authenticator) CreateSession(username, password string) (string, error) {

	if err := a.Authenticate(username, password); err != nil {
		return "", err
	}

	if existingSession, ok := a.rdx.GetLastVal(UsernameSessionProperty, username); ok && existingSession != "" {
		return existingSession, nil
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

func (a *Authenticator) ValidateSession(session string) error {

	if scs, ok := a.rdx.GetLastVal(SessionCreatedProperty, session); ok && scs != "" {

		sct, err := http.ParseTime(scs)
		if err != nil {
			return err
		}

		utcNow := time.Now().UTC()
		sessionExpires := sct.Add(defaultSessionDurationDays * time.Hour * 24)

		// that's the only successful condition, otherwise the session is not valid
		if utcNow.Before(sessionExpires) {
			return nil
		} else {
			if err = a.CutSession(session); err != nil {
				return err
			}
			return ErrSessionExpired
		}

	}

	return ErrSessionNotValid
}

func (a *Authenticator) CutSession(session string) error {

	query := map[string][]string{UsernameSessionProperty: {session}}

	for username := range a.rdx.Match(query, redux.FullMatch) {
		if err := a.rdx.CutValues(UsernameSessionProperty, username, session); err != nil {
			return err
		}
	}

	return a.rdx.CutKeys(SessionCreatedProperty, session)
}

func (a *Authenticator) CutUserSessions(username string) error {

	if userSessions, ok := a.rdx.GetAllValues(UsernameSessionProperty, username); ok {
		if err := a.rdx.CutKeys(SessionCreatedProperty, userSessions...); err != nil {
			return err
		}
	}

	return a.rdx.CutKeys(UsernameSessionProperty, username)
}

func (a *Authenticator) GetSessionPermissions(session string) ([]Permission, error) {

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
