package author

import (
	"net/http"
	"time"
)

func (b *Bouncer) PostLogin(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if username := r.PostFormValue(UsernameParam); username != "" {
		if password := r.PostFormValue(PasswordParam); password != "" {

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
				return

			}

		}
	}

	http.Error(w, "Unauthorized access attempt detected", http.StatusUnauthorized)
}
