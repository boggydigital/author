package author

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/boggydigital/redux"
	"golang.org/x/crypto/bcrypt"
)

type Authenticator struct {
	rdx             redux.Writeable
	rolePermissions map[string][]Permission
}

func NewAuthenticator(dir string, rolePermissions map[string][]Permission) (*Authenticator, error) {

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

	return a.rdx.CutKeys(UsernamePasswordProperty, username)
}

func (a *Authenticator) SetRole(username, password, role string) error {

	if err := a.Authenticate(username, password); err != nil {
		return err
	}

	return a.rdx.AddValues(UsernameRoleProperty, role)
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
	sessionStarted := time.Now().UTC().Format(time.RFC3339)

	if err := a.rdx.ReplaceValues(SessionStartedProperty, session, sessionStarted); err != nil {
		return "", err
	}

	if err := a.rdx.AddValues(UsernameSessionProperty, username, session); err != nil {
		return "", err
	}

	return session, nil
}

const (
	sessionExpirationDays = 30
)

func (a *Authenticator) RefreshSession(session string) error {

	if sessionStarted, ok := a.rdx.GetLastVal(SessionStartedProperty, session); ok && sessionStarted != "" {

		if sessionStartedTime, err := time.Parse(time.RFC3339, sessionStarted); err == nil {

			if time.Now().UTC().After(sessionStartedTime.Add(sessionExpirationDays * 24 * time.Hour)) {

				if err = a.rdx.CutKeys(SessionStartedProperty, session); err != nil {
					return err
				}

				return ErrSessionExpired
			}

		} else {
			return err
		}

	} else {
		return ErrSessionExpired
	}

	sessionRestarted := time.Now().UTC().Format(time.RFC3339)

	return a.rdx.ReplaceValues(SessionStartedProperty, session, sessionRestarted)
}

func (a *Authenticator) CutSessions(username string) error {
	return a.rdx.CutKeys(UsernameSessionProperty, username)
}

func (a *Authenticator) GetSessionPermissions(session string) ([]Permission, error) {
	return nil, nil
}
