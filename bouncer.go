package author

import (
	"net/http"
)

const CookieKeySession = "Session"

type Bouncer struct {
	author    *Authenticator
	loginPath string
}

func NewBouncer(dir string, rolePermissions map[string][]Permission, loginPath string) (*Bouncer, error) {

	author, err := NewAuthenticator(dir, rolePermissions)
	if err != nil {
		return nil, err
	}

	return &Bouncer{
		author:    author,
		loginPath: loginPath,
	}, nil
}

func Auth(b *Bouncer, next http.Handler) http.Handler {
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

				if b.author.IsValidSession(cookie.Value) {
					next.ServeHTTP(w, r)
				}

			}
		}

		http.Redirect(w, r, b.loginPath, http.StatusTemporaryRedirect)
	})
}
