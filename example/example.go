package example

import (
	"fmt"

	"github.com/Salahuddeen/MyHealthPassLib/pkg/auth"
)

func main() {

	JWTSecret := "forzaHorizon"

	dataStoreMoq := &auth.DataStoreMock{}

	authLib := auth.InitAuthLib(dataStoreMoq, JWTSecret)

	username := "yubikey"
	password := "star"

	account, err := authLib.Register(auth.Account{
		Username: "yubikey",
	},
		password,
	)
	if err != nil {
		fmt.Printf("unable to register")
	}
	fmt.Printf("Account returned %#v", account)

	token, err := authLib.Login(username, password)
	if err != nil {
		fmt.Print("unable to login")
	}

	isAuthenticated := authLib.Authenticate(token)
	if !isAuthenticated {
		fmt.Printf("unable to authenticate")
	}

}
