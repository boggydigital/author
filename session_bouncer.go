package author

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const applicationJsonContentType = "application/json"

const CookieKeySession = "Session"

const (
	LoginPath   = "login"
	SuccessPath = "success"
)

type SessionTokenExpires struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type SessionBouncer struct {
	author      Authenticator
	loginPath   string
	successPath string
}

func NewSessionBouncer(dir string, rolePermissions map[string][]Permission, paths map[string]string) (*SessionBouncer, error) {

	author, err := NewAuthenticator(dir, rolePermissions)
	if err != nil {
		return nil, err
	}

	sb := &SessionBouncer{
		author: author,
	}

	if lp, ok := paths[LoginPath]; ok {
		sb.loginPath = lp
	} else {
		return nil, errors.New("login path is required")
	}

	if sp, ok := paths[SuccessPath]; ok {
		sb.successPath = sp
	} else {
		return nil, errors.New("success path is required")
	}

	return sb, nil
}

func cookieSessionToken(r *http.Request) (string, error) {

	if cookieHeader := r.Header.Get("Cookie"); cookieHeader != "" {

		cookies, err := http.ParseCookie(cookieHeader)
		if err != nil {
			return "", err
		}

		for _, cookie := range cookies {

			if cookie.Name != CookieKeySession {
				continue
			}

			return cookie.Value, nil
		}
	}

	return "", ErrSessionNotValid
}

func authorizationBearerToken(r *http.Request) (string, error) {

	if abt := r.Header.Get("Authorization"); abt != "" && strings.HasPrefix(abt, "Bearer ") {
		return strings.TrimPrefix(abt, "Bearer "), nil
	}

	return "", ErrSessionNotValid
}

func AuthSessionToken(b *SessionBouncer, next http.Handler, requiredPermissions ...Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var sessionToken string

		if st, err := cookieSessionToken(r); errors.Is(err, ErrSessionExpired) ||
			errors.Is(err, ErrSessionNotValid) {
			http.Redirect(w, r, b.loginPath, http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else {
			sessionToken = st
		}

		if sessionToken == "" {
			if abt, err := authorizationBearerToken(r); errors.Is(err, ErrSessionExpired) ||
				errors.Is(err, ErrSessionNotValid) {
				http.Redirect(w, r, b.loginPath, http.StatusTemporaryRedirect)
				return
			} else if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			} else {
				sessionToken = abt
			}
		}

		if err := b.author.AuthenticateSession(sessionToken); errors.Is(err, ErrSessionExpired) ||
			errors.Is(err, ErrSessionNotValid) {
			http.Redirect(w, r, b.loginPath, http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		} else {

			if err = b.author.MustHaveSessionPermissions(sessionToken, requiredPermissions...); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			next.ServeHTTP(w, r)
			return
		}

	})
}

func (sb *SessionBouncer) AuthBrowserSession(w http.ResponseWriter, r *http.Request) {

	if ste, err := sb.authSession(r); errors.Is(err, ErrUsernamePasswordMissing) ||
		errors.Is(err, ErrUsernamePasswordMismatch) {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		cookie := &http.Cookie{
			Name:        CookieKeySession,
			Value:       ste.Token,
			Expires:     ste.Expires,
			Secure:      true,
			HttpOnly:    true,
			SameSite:    http.SameSiteStrictMode,
			Partitioned: false,
		}

		http.SetCookie(w, cookie)
		http.Redirect(w, r, sb.successPath, http.StatusTemporaryRedirect)
		return
	}
}

func (sb *SessionBouncer) AuthApiSession(w http.ResponseWriter, r *http.Request) {

	if ste, err := sb.authSession(r); errors.Is(err, ErrUsernamePasswordMissing) ||
		errors.Is(err, ErrUsernamePasswordMismatch) {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else {
		w.Header().Set("Content-Type", applicationJsonContentType)

		if err = json.NewEncoder(w).Encode(ste); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
}

func (sb *SessionBouncer) authSession(r *http.Request) (*SessionTokenExpires, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	if username := r.FormValue(UsernameParam); username != "" {
		if password := r.FormValue(PasswordParam); password != "" {

			if sessionToken, err := sb.author.CreateSession(username, password); err != nil {
				return nil, err
			} else {

				var seu time.Time
				seu, err = sb.author.SessionExpiresUtc(sessionToken)
				if err != nil {
					return nil, err
				}

				ste := &SessionTokenExpires{
					Token:   sessionToken,
					Expires: seu,
				}

				return ste, nil
			}
		}
	}

	return nil, ErrUsernamePasswordMissing
}
