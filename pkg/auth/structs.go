package auth

// MyHealthAuth authentication interface.
type MyHealthAuth interface {
	login(username, password string) bool
	register(accountDetails AccountDetails, password string) AccountDetails
	authenticate(token string) bool
}

type AccountDetails struct {
	AccountID   string
	Name        string
	DateOfBirth string

	AccountAuthDetails
}

type AccountAuthDetails struct {
	PasswordHash      string
	LastLogin         string
	AccountLoginState bool
	LoginAttempts     int
}
