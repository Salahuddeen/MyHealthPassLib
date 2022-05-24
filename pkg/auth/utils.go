package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

func (a *AuthLib) userExists(username string) bool {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "userExists",
		},
	)
	logger.Trace("starting userExists method")

	return a.dataStore.getAccount(username) != nil
}

func (a *AuthLib) validatePassword(password string) (err error) {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "validatePassword",
		},
	)
	logger.Trace("starting validatePassword method")

	if password == "" {
		return errors.New("password should not be empty")
	}

	logger.Trace("password validation successful")
	return
}

func (a *AuthLib) accountActive(username string) bool {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "accountIsLocked",
		},
	)
	logger.Trace("starting accountIsLocked method")

	account := a.dataStore.getAccount(username)

	if account.accountActive {
		logger.Trace("Account is not locked")
		return true
	} else {

		/*
		   If account is locked and the timestamp + interval  < time.Now(), unlock.
		   else return false
		*/

		// Check the timestamp.
		reActTime := time.Unix(account.firstFailTimestamp, 0).Add(time.Duration(a.lockoutInterval) * time.Minute)

		if time.Now().After(reActTime) {
			account.accountActive = true
			account.firstFailTimestamp = 0
			account.failedLoginAttempts = 0
			_, err := a.dataStore.updateAccount(account)
			if err != nil {
				logger.Errorf("unable to reset account lockout with error %s", err.Error())
				return false
			}
			return true
		} else {
			account.failedLoginAttempts = account.failedLoginAttempts + 1
			_, err := a.dataStore.updateAccount(account)
			if err != nil {
				logger.Errorf("increment failed login counter with error %s", err.Error())
				return false
			}
		}
	}

	logger.Debug("account is locked, timeout has not expired.")
	return false

	// TODO:
	// Document me!
	// Add logic for unlocking accounts if timeframe has been exceeded.
	// Add configuration to the Authlib for length of time the account is locked for.

}

func (a *AuthLib) attemptLogin(username, password string) bool {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "verifyLogin",
		},
	)
	logger.Trace("starting verifyLogin method")

	// TODO implement me. get user, get password check if password matches stored password.
	// if verification fails, increment failed attempt.
	// if last failed attempt date != 00000000
	// if now - last failed attempt date < interval, increment failed attempt.
	// if now - last failed attempt date > interval , last failed attempt date = now.
	// if failed attempt count == max failed attempts, lock account. return false.

	authDetails := a.dataStore.getAccount(username)

	err := bcrypt.CompareHashAndPassword(authDetails.password, []byte(password))
	if err != nil {

		logger.Errorf("invalid password")
		authDetails.failedLoginAttempts = authDetails.failedLoginAttempts + 1

		if authDetails.firstFailTimestamp != 0 {
			// This isn't the first failure
			// verify that interval has not passed since last attempt.
			// if interval has passed, we reset to now and set attempts to 1.

			logger.Debug("checking last login attempt")
			lastFailureStart := time.Unix(authDetails.firstFailTimestamp, 0)
			lastFailureStart = lastFailureStart.Add(a.lockoutInterval)

			if time.Now().After(lastFailureStart) {
				logger.Debug("interval between failures is greater than configured; setting to now")
				authDetails.firstFailTimestamp = time.Now().Unix()
				authDetails.failedLoginAttempts = 1
			}
		} else {
			// Set to now.
			logger.Debug("setting last login attempt to now")
			authDetails.firstFailTimestamp = time.Now().Unix()
		}

		// if failure happens, we lock the account

		if authDetails.failedLoginAttempts >= a.loginAttemptsBeforeLockout {
			logger.Error("locking account, login attempts exceeded")
			// Lock account if attempts is greater than lockout.
			authDetails.accountActive = false
			authDetails.firstFailTimestamp = time.Now().Unix()
		}

		a.dataStore.updateAccount(authDetails)
		return false

	}

	return true

}

func (a *AuthLib) generateJWT(username string) (token string, err error) {
	logger := a.logger.WithFields(
		log.Fields{
			"method": "generateJWT",
		},
	)
	logger.Trace("starting generateJWT method")

	expiration := time.Now().Add(time.Duration(10) * time.Minute)

	cl := claims{
		username,
		jwt.StandardClaims{
			NotBefore: time.Now().Unix(),
			ExpiresAt: expiration.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)

	return tk.SignedString(a.jwtSecret)
}
