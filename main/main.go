package main

import (
	"fmt"
	"os"

	"github.com/boggydigital/author"
)

func main() {

	authDir := os.TempDir()

	at, err := author.NewAuthenticator(authDir, nil)
	if err != nil {
		panic(err)
	}

	username := "user"

	if !at.HasUser(username) {
		if err = at.CreateUser(username, "password"); err != nil {
			panic(err)
		}

		fmt.Printf("user created")
	}

	// if err = at.CutSessions(username); err != nil {
	// 	panic(err)
	// }

	if session, err := at.CreateSession(username, "password"); err != nil {
		panic(err)
	} else {

		if err = at.RefreshSession(session); err != nil {
			panic(err)
		}

		fmt.Println(session)
	}

}
