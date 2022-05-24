package auth

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

var testLogger = log.New()

func TestAuthLib_userExists(t *testing.T) {

	dataStoreMoq := DataStoreMock{
		getAccountFunc: func(username string) *Account {
			switch username {
			case "folley":
				return &Account{
					Username:            "folley",
					password:            []byte("spi"),
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 0,
					firstFailTimestamp:  0,
				}

			default:
				return nil
			}
		},
	}

	type args struct {
		username string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid user",
			args: args{
				username: "folley",
			},
			want: true,
		},
		{
			name: "invalid user",
			args: args{
				username: "oflofski",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            20,
				loginAttemptsBeforeLockout: 20,
				jwtSecret:                  []byte("hi"),
			}
			if got := a.userExists(tt.args.username); got != tt.want {
				t.Errorf("AuthLib.userExists() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthLib_validatePassword(t *testing.T) {

	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				password: "iamvalid",
			},
			wantErr: false,
		},
		{
			name: "invalid",
			args: args{
				password: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     testLogger,
				dataStore:                  nil,
				lockoutInterval:            20,
				loginAttemptsBeforeLockout: 20,
				jwtSecret:                  []byte("hi"),
			}
			if err := a.validatePassword(tt.args.password); (err != nil) != tt.wantErr {
				t.Errorf("AuthLib.validatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthLib_accountIsLocked(t *testing.T) {

	testLogger.SetLevel(log.TraceLevel)
	testLogger.SetOutput(os.Stdout)

	dataStoreMoq := DataStoreMock{
		getAccountFunc: func(username string) *Account {
			switch username {
			case "folley":
				return &Account{
					Username:            "folley",
					password:            []byte("spi"),
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 0,
					firstFailTimestamp:  0,
				}

			case "Locked":
				return &Account{
					Username:            "Locked",
					password:            []byte("spider"),
					lastLogin:           "",
					accountActive:       false,
					failedLoginAttempts: 4,
					firstFailTimestamp:  time.Now().Unix(),
				}

			case "unlockMe":

				timestamp := time.Now().Add(time.Duration(-20) * time.Minute)

				return &Account{
					Username:            "unlockMe",
					password:            []byte("gor"),
					lastLogin:           "",
					accountActive:       false,
					failedLoginAttempts: 2,
					firstFailTimestamp:  timestamp.Unix(),
				}

			default:
				t.Fatal("unexpected username sent to datastore")
				return nil
			}
		},
		updateAccountFunc: func(account *Account) (*Account, error) {
			switch account.Username {

			case "Locked":
				assert.Equal(t, 5, account.failedLoginAttempts)
				return account, nil

			case "unlockMe":
				assert.Equal(t, int64(0), account.firstFailTimestamp)
				assert.Equal(t, 0, account.failedLoginAttempts)
				assert.True(t, account.accountActive)
				return account, nil

			default:
				t.Errorf("unexpected call to update account")
				return nil, errors.New("unexpected call to update account")
			}
		},
	}

	type fields struct {
		logger                     *log.Logger
		dataStore                  DataStore
		lockoutInterval            time.Duration
		loginAttemptsBeforeLockout int
		jwtSecret                  []byte
	}
	type args struct {
		username string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		want        bool
		updateCalls int
		getCalls    int
	}{
		{
			name: "not locked",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            10,
				loginAttemptsBeforeLockout: 15,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "folley",
			},
			want:        true,
			getCalls:    1,
			updateCalls: 0,
		},
		{
			name: "locked account, within lockout period",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            20,
				loginAttemptsBeforeLockout: 15,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "Locked",
			},
			want:        false,
			getCalls:    2, // Mock should be called twice, We can get around this by using a mock per test.
			updateCalls: 1,
		},
		{
			name: "locked account, outside lockout period",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            1,
				loginAttemptsBeforeLockout: 15,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "unlockMe",
			},
			want:        true,
			getCalls:    3, // Mock should be called thrice
			updateCalls: 2, // previous test also calls update
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     tt.fields.logger,
				dataStore:                  tt.fields.dataStore,
				lockoutInterval:            tt.fields.lockoutInterval,
				loginAttemptsBeforeLockout: tt.fields.loginAttemptsBeforeLockout,
				jwtSecret:                  tt.fields.jwtSecret,
			}
			if got := a.accountActive(tt.args.username); got != tt.want {
				t.Errorf("AuthLib.accountIsLocked() = %v, want %v", got, tt.want)
			}

			assert.Equal(t, tt.getCalls, len(dataStoreMoq.getAccountCalls()))
			assert.Equal(t, tt.updateCalls, len(dataStoreMoq.updateAccountCalls()))

		})
	}
}

func TestAuthLib_attemptLogin(t *testing.T) {

	testLogger.SetLevel(log.TraceLevel)
	testLogger.SetOutput(os.Stdout)

	// Generate a password for testing
	password, err := bcrypt.GenerateFromPassword([]byte("f1f1in!s@"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	err = bcrypt.CompareHashAndPassword(password, []byte("f1f1in!s@"))
	assert.NoError(t, err)

	password2, err := bcrypt.GenerateFromPassword([]byte("f1f1in!122s@"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	dataStoreMoq := DataStoreMock{
		getAccountFunc: func(username string) *Account {
			switch username {
			case "folley":
				return &Account{
					Username:            "folley",
					password:            password,
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 0,
					firstFailTimestamp:  0,
				}

			case "failme":
				return &Account{
					Username:            "failme",
					password:            password,
					lastLogin:           "1653364364",
					accountActive:       true,
					failedLoginAttempts: 4,
					firstFailTimestamp:  time.Now().Unix(),
				}

			case "lockMe":
				return &Account{
					Username:            "lockMe",
					password:            password2,
					lastLogin:           "",
					accountActive:       false,
					failedLoginAttempts: 4,
					firstFailTimestamp:  time.Now().Unix(),
				}

			default:
				t.Fatal("unexpected username sent to datastore")
				return nil
			}
		},
		updateAccountFunc: func(account *Account) (*Account, error) {
			switch account.Username {

			case "failme":
				// This account does not get locked, but fails the password check
				assert.NotEqual(t, int64(0), account.firstFailTimestamp)
				assert.Equal(t, 1, account.failedLoginAttempts)
				assert.True(t, account.accountActive)
				return account, nil

			case "lockMe":
				// This account gets locked
				assert.False(t, account.accountActive)
				assert.Equal(t, 5, account.failedLoginAttempts)
				assert.NotEqual(t, int64(0), account.firstFailTimestamp)
				return account, nil

			default:
				t.Errorf("unexpected call to update account with username %s", account.Username)
				return nil, fmt.Errorf("unexpected call to update account with username %s", account.Username)
			}
		},
	}

	type fields struct {
		logger                     *log.Logger
		dataStore                  DataStore
		lockoutInterval            time.Duration
		loginAttemptsBeforeLockout int
		jwtSecret                  []byte
	}
	type args struct {
		username string
		password string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		want        bool
		accLock     bool
		getCalls    int
		updateCalls int
	}{
		{
			name: "success",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            time.Duration(30),
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "folley",
				password: "f1f1in!s@",
			},
			want:        true,
			accLock:     false,
			getCalls:    1,
			updateCalls: 0,
		},
		{
			name: "failure - account not locked",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            time.Duration(30),
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "failme",
				password: "12321312",
			},
			want:        false,
			accLock:     false,
			getCalls:    2,
			updateCalls: 1,
		},
		{
			name: "lock account",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  &dataStoreMoq,
				lockoutInterval:            time.Duration(30) * time.Minute,
				loginAttemptsBeforeLockout: 3,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "lockMe",
				password: "12321312",
			},
			want:        false,
			accLock:     true,
			getCalls:    3,
			updateCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     tt.fields.logger,
				dataStore:                  tt.fields.dataStore,
				lockoutInterval:            tt.fields.lockoutInterval,
				loginAttemptsBeforeLockout: tt.fields.loginAttemptsBeforeLockout,
				jwtSecret:                  tt.fields.jwtSecret,
			}
			if got := a.attemptLogin(tt.args.username, tt.args.password); got != tt.want {
				t.Errorf("AuthLib.attemptLogin() = %v, want %v", got, tt.want)
			}

			assert.Equal(t, tt.getCalls, len(dataStoreMoq.getAccountCalls()))
			assert.Equal(t, tt.updateCalls, len(dataStoreMoq.updateAccountCalls()))

		})
	}
}

func TestAuthLib_generateJWT(t *testing.T) {
	type fields struct {
		logger                     *log.Logger
		dataStore                  DataStore
		lockoutInterval            time.Duration
		loginAttemptsBeforeLockout int
		jwtSecret                  []byte
	}
	type args struct {
		username string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantToken bool
		wantErr   bool
	}{
		{
			name: "jwt generated",
			fields: fields{
				logger:                     testLogger,
				dataStore:                  nil,
				lockoutInterval:            0,
				loginAttemptsBeforeLockout: 0,
				jwtSecret:                  []byte("hi"),
			},
			args: args{
				username: "fred",
			},
			wantToken: true,
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthLib{
				logger:                     tt.fields.logger,
				dataStore:                  tt.fields.dataStore,
				lockoutInterval:            tt.fields.lockoutInterval,
				loginAttemptsBeforeLockout: tt.fields.loginAttemptsBeforeLockout,
				jwtSecret:                  tt.fields.jwtSecret,
			}
			gotToken, err := a.generateJWT(tt.args.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthLib.generateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantToken {
				// check if token is valid
				jwtToken, err := jwt.ParseWithClaims(gotToken, &claims{}, func(t *jwt.Token) (interface{}, error) {
					return tt.fields.jwtSecret, nil
				})

				assert.NoError(t, err)
				if claims, ok := jwtToken.Claims.(*claims); ok && jwtToken.Valid {

					username := claims.Username
					exp := claims.NotBefore

					expiry := time.Unix(exp, 0)

					assert.NotEmpty(t, username)
					assert.NotEmpty(t, expiry)

					assert.Equal(t, tt.args.username, username)

				} else {
					t.Errorf("unable to parse claims on jwt")
				}
			}
		})
	}
}
