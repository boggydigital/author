package author

import (
	"net/http"
	"time"
)

func (b *Bouncer) Authenticate(w http.ResponseWriter, r *http.Request) {

	q := r.URL.Query()

	if username := q.Get(UsernameParam); username != "" {
		if password := q.Get(PasswordParam); password != "" {

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
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

				return
			}

		}
	}

	http.Error(w, "Unauthorized access attempt detected", http.StatusUnauthorized)
}
