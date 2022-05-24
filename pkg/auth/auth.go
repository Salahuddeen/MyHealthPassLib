package auth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthLib struct {
	logger                     *log.Logger
	dataStore                  DataStore
	lockoutInterval            time.Duration
	loginAttemptsBeforeLockout int
	jwtSecret                  []byte
}

func InitAuthLib(dataStore DataStore, jwtSecret string) *AuthLib {

	// Setup a logrus logger.
	// Set it to output to nowhere.
	logger := log.New()
	logger.SetOutput(ioutil.Discard)

	return &AuthLib{
		logger:                     logger,
		dataStore:                  dataStore,
		lockoutInterval:            time.Minute * 20,
		loginAttemptsBeforeLockout: 20,
		jwtSecret:                  []byte(jwtSecret),
	}
}

func (a *AuthLib) EnableLogging() {

	// Turns on Logrus logger
	log.SetOutput(os.Stdout)
}

func (a *AuthLib) SetLockoutInterval(interval int) {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "SetLockoutInterval",
		},
	)
	logger.Trace("starting SetLockoutInterval method")

	a.lockoutInterval = time.Duration(time.Minute * time.Duration(interval))
}

// Login performs a user login action.
func (a *AuthLib) Login(username, password string) (token string, err error) {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "login",
		},
	)
	logger.Trace("starting login method")

	if username == "" {
		return "", errors.New("user does not exist")
	}

	if !a.userExists(username) {
		return "", errors.New("user does not exist")
	}

	if !a.accountActive(username) {
		return "", errors.New("user account is locked, please try again later")
	}

	if !a.attemptLogin(username, password) {
		return "", errors.New("invalid credentials, please try again")
	}

	jwt, err := a.generateJWT(username)
	if err != nil {
		return "", fmt.Errorf("unable to generate JWT with error %s", err.Error())
	}

	return jwt, nil
}

// Register creates a new user
func (a *AuthLib) Register(accountDetails Account, password string) (*Account, error) {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "register",
		},
	)
	logger.Trace("starting register method")

	// Validate some things about the user

	if accountDetails.Username == "" {
		logger.Error("username not set")
		return nil, errors.New("username not set")
	}

	err := a.validatePassword(password)
	if err != nil {
		logger.Errorf("invalid password, %s", err.Error())
		return nil, err
	}

	if a.userExists(accountDetails.Username) {
		logger.Errorf("user already exists")
		return nil, errors.New("user already exists")
	}

	// Set user Auth details

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("unable to generate password")
		return nil, err
	}

	accAuth := Account{
		Username:            accountDetails.Username,
		password:            passwordHash,
		lastLogin:           "",
		accountActive:       true,
		failedLoginAttempts: 0,
		firstFailTimestamp:  0,
	}

	// Everything looks good, lets create the user.
	err = a.dataStore.createAccount(&accAuth)
	if err != nil {
		logger.Errorf("unable to create user with error %s", err.Error())
		return nil, err
	}

	return &accAuth, nil
}

// Authenticate vaidates a JWT created by a user
func (a *AuthLib) Authenticate(token string) bool {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "authenticate",
		},
	)
	logger.Trace("starting authenticate method")

	jwtToken, err := jwt.ParseWithClaims(token, &claims{}, func(t *jwt.Token) (interface{}, error) {
		return a.jwtSecret, nil
	})

	if err != nil {
		logger.Error("unable to parse jwt")
		return false
	}

	if claims, ok := jwtToken.Claims.(*claims); ok && jwtToken.Valid {

		username := claims.Username
		exp := claims.ExpiresAt

		expiry := time.Unix(exp, 0)

		if username == "" {
			logger.Error("username not set in jwt")
			return false
		}

		if !a.userExists(username) {
			logger.Error("user does not exist")
			return false
		}

		if time.Now().After(expiry) {
			logger.Error("jwt expired")
			return false
		}
	} else {
		logger.Error("invalid claims on jwt")
		return false
	}

	logger.Trace("token valid")
	return true
}
