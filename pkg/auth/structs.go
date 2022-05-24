package auth

import "github.com/golang-jwt/jwt"

// MyHealthAuth authentication interface.
type MyHealthAuth interface {
	Login(username, password string) (error, token string)
	Register(accountDetails Account, password string) (*Account, error)
	Authenticate(token string) error
}

//go:generate moq -out DataStoreMoq.go . DataStore

// DataStore manages database communication between the library and datastore.
type DataStore interface {
	getAccount(username string) *Account
	createAccount(account *Account) (err error)
	updateAccount(*Account) (updatedAccount *Account, err error)
}

type Account struct {
	Username            string
	password            []byte
	lastLogin           string
	accountActive       bool
	failedLoginAttempts int
	firstFailTimestamp  int64
}

type claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
