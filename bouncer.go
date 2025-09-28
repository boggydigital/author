package author

import (
	"errors"
	"net/http"
	"time"
)

const CookieKeySession = "Session"

type Bouncer struct {
	author      *Authenticator
	loginPath   string
	successPath string
}

func NewBouncer(dir string, rolePermissions map[string][]Permission, loginPath, successPath string) (*Bouncer, error) {

	author, err := NewAuthenticator(dir, rolePermissions)
	if err != nil {
		return nil, err
	}

	return &Bouncer{
		author:      author,
		loginPath:   loginPath,
		successPath: successPath,
	}, nil
}

func AuthenticateSession(b *Bouncer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if cookieHeader := r.Header.Get("Cookie"); cookieHeader != "" {
			cookies, err := http.ParseCookie(cookieHeader)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			for _, cookie := range cookies {

				if cookie.Name != CookieKeySession {
					continue
				}

				if err = b.author.ValidateSession(cookie.Value); errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionNotValid) {
					http.Redirect(w, r, b.loginPath, http.StatusTemporaryRedirect)
					return
				} else if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				next.ServeHTTP(w, r)

			}
		}

		http.Redirect(w, r, b.loginPath, http.StatusTemporaryRedirect)
	})
}

func (b *Bouncer) Authenticate(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if username := r.FormValue(UsernameParam); username != "" {
		if password := r.FormValue(PasswordParam); password != "" {

			if session, err := b.author.CreateSession(username, password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			} else {

				expires := time.Now().UTC().Add(defaultSessionDurationDays * time.Hour * 24)

				cookie := &http.Cookie{
					Name:        CookieKeySession,
					Value:       session,
					Expires:     expires,
					Secure:      true,
					HttpOnly:    true,
					SameSite:    http.SameSiteStrictMode,
					Partitioned: false,
				}

				http.SetCookie(w, cookie)
				http.Redirect(w, r, b.successPath, http.StatusTemporaryRedirect)

				return
			}

		}
	}

	http.Error(w, "Unauthorized access attempt detected", http.StatusUnauthorized)
}
