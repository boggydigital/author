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

type SessionTokenExpires struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

type SessionBouncer struct {
	author          Authenticator
	loginPath       string
	insecureCookies bool
}

func NewSessionBouncer(dir string, rolePermissions map[string][]Permission, loginPath string, insecureCookies bool) (*SessionBouncer, error) {

	author, err := NewAuthenticator(dir, rolePermissions)
	if err != nil {
		return nil, err
	}

	sb := &SessionBouncer{
		author:          author,
		insecureCookies: insecureCookies,
	}

	switch loginPath {
	case "":
		return nil, errors.New("login path is required")
	default:
		sb.loginPath = loginPath
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

func AuthSessionCookie(sb *SessionBouncer, next http.Handler, requiredPermissions ...Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		sessionToken, err := cookieSessionToken(r)
		if errors.Is(err, ErrSessionNotValid) {
			http.Redirect(w, r, sb.loginPath, http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err = sb.authSessionToken(sessionToken, requiredPermissions...); errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionNotValid) {
			http.Redirect(w, r, sb.loginPath, http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
		return
	})
}

func AuthSessionBearer(sb *SessionBouncer, next http.Handler, requiredPermissions ...Permission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		sessionToken, err := authorizationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if err = sb.authSessionToken(sessionToken, requiredPermissions...); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
		return
	})
}

func (sb *SessionBouncer) MustHaveUsers() error {
	return sb.author.MustHaveUsers()
}

func (sb *SessionBouncer) authSessionToken(sessionToken string, requiredPermissions ...Permission) error {
	if err := sb.author.AuthenticateSession(sessionToken); err != nil {
		return err
	} else {
		if err = sb.author.MustHaveSessionPermissions(sessionToken, requiredPermissions...); err != nil {
			return err
		}
	}
	return nil
}

func (sb *SessionBouncer) AuthBrowserUsernamePassword(w http.ResponseWriter, r *http.Request) {

	if ste, err := sb.authUsernamePassword(r); errors.Is(err, ErrUsernamePasswordMissing) ||
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
			Secure:      !sb.insecureCookies,
			HttpOnly:    true,
			SameSite:    http.SameSiteStrictMode,
			Partitioned: false,
		}

		http.SetCookie(w, cookie)
		w.Header().Set("Location", "/")

		w.WriteHeader(http.StatusSeeOther)

		return
	}
}

func (sb *SessionBouncer) AuthApiUsernamePassword(w http.ResponseWriter, r *http.Request) {

	if ste, err := sb.authUsernamePassword(r); errors.Is(err, ErrUsernamePasswordMissing) ||
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

func (sb *SessionBouncer) AuthApiSession(w http.ResponseWriter, r *http.Request) {

	if ste, err := sb.authSessionBearer(r); errors.Is(err, ErrSessionNotValid) ||
		errors.Is(err, ErrSessionExpired) {
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

func (sb *SessionBouncer) authUsernamePassword(r *http.Request) (*SessionTokenExpires, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	if username := r.FormValue(UsernameParam); username != "" {
		if password := r.FormValue(PasswordParam); password != "" {

			if sessionToken, err := sb.author.CreateSession(username, password); err != nil {
				return nil, err
			} else {

				var sessionExpires time.Time
				sessionExpires, err = sb.author.SessionExpires(sessionToken)
				if err != nil {
					return nil, err
				}

				ste := &SessionTokenExpires{
					Token:   sessionToken,
					Expires: sessionExpires,
				}

				return ste, nil
			}
		}
	}

	return nil, ErrUsernamePasswordMissing
}

func (sb *SessionBouncer) authSessionBearer(r *http.Request) (*SessionTokenExpires, error) {

	sessionToken, err := authorizationBearerToken(r)
	if err != nil {
		return nil, err
	}

	if err = sb.author.AuthenticateSession(sessionToken); err != nil {
		return nil, err
	}

	sessionExpires, err := sb.author.SessionExpires(sessionToken)
	if err != nil {
		return nil, err
	}

	ste := &SessionTokenExpires{
		Token:   sessionToken,
		Expires: sessionExpires,
	}

	return ste, nil
}

func (sb *SessionBouncer) DeauthCookieSession(w http.ResponseWriter, r *http.Request) {

	sessionToken, err := cookieSessionToken(r)
	if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionNotValid) {
		// do nothing, session already invalid
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = sb.author.CutSession(sessionToken); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (sb *SessionBouncer) DeauthSessionBearer(w http.ResponseWriter, r *http.Request) {

	sessionToken, err := authorizationBearerToken(r)
	if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionNotValid) {
		// do nothing, session already invalid
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err = sb.author.CutSession(sessionToken); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (sb *SessionBouncer) GetCookiePermissions(r *http.Request) ([]Permission, error) {

	sessionToken, err := cookieSessionToken(r)
	if err != nil {
		return nil, err
	}

	return sb.author.GetSessionPermissions(sessionToken)
}

func (sb *SessionBouncer) GetBearerPermissions(r *http.Request) ([]Permission, error) {
	sessionToken, err := authorizationBearerToken(r)
	if err != nil {
		return nil, err
	}

	return sb.author.GetSessionPermissions(sessionToken)
}
